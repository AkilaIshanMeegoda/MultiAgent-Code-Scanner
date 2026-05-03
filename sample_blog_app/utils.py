"""
sample_blog_app/utils.py
Utility functions — contains bug and optimisation issues.
"""

import os
import re
import time
import subprocess


# ─── SECURITY ISSUE: shell injection via subprocess ──────────────────────────
def generate_thumbnail(image_path: str) -> str:
    """Generate image thumbnail using ImageMagick."""
    output_path = image_path.replace(".", "_thumb.")
    # Vulnerable: image_path not sanitised — allows shell injection
    cmd = f"convert {image_path} -resize 200x200 {output_path}"
    os.system(cmd)
    return output_path


# ─── SECURITY ISSUE: path traversal in file read ─────────────────────────────
TEMPLATE_DIR = "/app/templates"

def load_template(name: str) -> str:
    """Load an email template from disk."""
    # No sanitisation — ../../etc/passwd works
    path = os.path.join(TEMPLATE_DIR, name)
    with open(path, "r") as f:
        return f.read()


# ─── BUG: mutable default argument ───────────────────────────────────────────
def parse_tags(raw: str, result=[]) -> list:
    """Parse comma-separated tags. Accumulates across calls due to mutable default."""
    for tag in raw.split(","):
        tag = tag.strip()
        if tag:
            result.append(tag.lower())
    return result


# ─── BUG: infinite loop risk — while True with fragile break condition ─────────
def wait_for_db(max_retries: int = 5):
    """Wait until database is available."""
    attempts = 0
    while True:
        # BUG: if os.path.exists never returns True, loops forever
        if os.path.exists("blog.db"):
            break
        time.sleep(1)
        # attempts counter is incremented but never used to break the loop
        attempts += 1


# ─── OPTIMISATION ISSUE: O(n²) duplicate detection ───────────────────────────
def deduplicate_tags(tags: list) -> list:
    """Remove duplicate tags from a list."""
    unique = []
    for tag in tags:
        found = False
        for existing in unique:
            # O(n²) — should use a set
            if existing == tag:
                found = True
                break
        if not found:
            unique.append(tag)
    return unique


# ─── OPTIMISATION ISSUE: regex compiled inside loop ──────────────────────────
def highlight_keywords(texts: list, keyword: str) -> list:
    """Wrap every occurrence of keyword in <b> tags across a list of texts."""
    results = []
    for text in texts:
        # Compiles the regex on every iteration — should compile once
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        results.append(pattern.sub(f"<b>{keyword}</b>", text))
    return results


# ─── BUG: off-by-one in pagination ───────────────────────────────────────────
def paginate(items: list, page: int, per_page: int = 10) -> list:
    """Return the items for a given page (1-indexed)."""
    start = (page - 1) * per_page
    end = start + per_page
    # BUG: when page=0 is passed, start=-10 — returns wrong slice
    return items[start:end]


# ─── BUG: function always returns None ───────────────────────────────────────
def calculate_reading_time(text: str) -> int:
    """Estimate reading time in minutes (avg 200 words/min)."""
    words = len(text.split())
    minutes = words // 200
    # BUG: result assigned but not returned
    result = max(1, minutes)


# ─── OPTIMISATION ISSUE: string concatenation in loop ────────────────────────
def build_html_list(items: list) -> str:
    """Build an HTML <ul> from a list of strings."""
    html = "<ul>"
    for item in items:
        # O(n) string copy on each += — should use join
        html += f"<li>{item}</li>"
    html += "</ul>"
    return html


# ─── SECURITY ISSUE: eval on user-supplied input ─────────────────────────────
def evaluate_filter_expression(expr: str, context: dict) -> bool:
    """
    Evaluate a filter expression like 'author == "alice"'.
    CRITICAL: uses eval() on untrusted input.
    """
    try:
        return bool(eval(expr, {}, context))  # noqa: S307
    except Exception:
        return False
