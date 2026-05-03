"""
Pattern-based fallback fix generator.

When the LLM is unavailable (Ollama 500 / OOM), this module generates
reasonable fixed code suggestions using simple string transformations and
known fix templates, keyed on the vulnerability/bug title produced by the
regex scanners.
"""

from __future__ import annotations

import re


# ── Vulnerability fix templates ───────────────────────────────────────────────
# Each entry: (substring_in_title, fix_fn)
# fix_fn(code_snippet) -> (fixed_code, explanation)

def _fix_sql_fstring(snippet: str) -> tuple[str, str]:
    # cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    # → cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    # Extract variable names from {var} in the f-string
    vars_found = re.findall(r"\{(\w+)\}", snippet)
    fixed = snippet
    # Remove f-prefix
    fixed = re.sub(r'\bf(["\'])', r'\1', fixed)
    # Replace {var} with ?
    for v in vars_found:
        fixed = fixed.replace(f"{{{v}}}", "?", 1)
    if vars_found:
        params = ", ".join(vars_found)
        # Append tuple argument if it looks like a complete statement
        if fixed.rstrip().endswith(")"):
            fixed = fixed.rstrip()[:-1] + f", ({params},))"
    return fixed, "Use parameterized query placeholders instead of f-string interpolation to prevent SQL injection."


def _fix_sql_percent(snippet: str) -> tuple[str, str]:
    # cursor.execute("SELECT * FROM users WHERE id = %s" % uid)
    # → cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    fixed = re.sub(r'%\s+(\w[\w\[\]\'\"\.]*)\s*$', r', (\1,))', snippet.rstrip())
    if fixed == snippet:
        fixed = re.sub(r'%\s+\(([^)]+)\)', r', (\1)', snippet)
    return fixed, "Pass parameters as a tuple argument instead of using % string formatting in SQL queries."


def _fix_sql_format(snippet: str) -> tuple[str, str]:
    # cursor.execute("SELECT ... WHERE id = {}".format(uid))
    vars_found = re.findall(r'\.format\s*\(([^)]+)\)', snippet)
    fixed = re.sub(r'\{\}', '?', snippet)
    fixed = re.sub(r'\.format\s*\([^)]+\)', '', fixed)
    if vars_found:
        params = vars_found[0]
        if fixed.rstrip().endswith(")"):
            fixed = fixed.rstrip()[:-1] + f", ({params},))"
    return fixed, "Use parameterized query placeholders instead of .format() to prevent SQL injection."


def _fix_hardcoded_credential(snippet: str) -> tuple[str, str]:
    # password = "my_secret" → password = os.environ.get('PASSWORD', '')
    match = re.match(r'(\s*)(password|secret|key|token|passwd|pwd)\s*=\s*[\'"][^\'"]*[\'"]',
                     snippet, re.IGNORECASE)
    if match:
        indent = match.group(1)
        var = match.group(2)
        env_var = var.upper()
        return (f"{indent}{var} = os.environ.get('{env_var}', '')",
                f"Load {var} from environment variable instead of hardcoding it in source.")
    return (f"# Load credentials from environment variables\nimport os\n{snippet.strip()}  # TODO: replace with os.environ.get()",
            "Store credentials in environment variables, not in source code.")


def _fix_weak_hash(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'\b(md5|sha1)\b', 'sha256', snippet, flags=re.IGNORECASE)
    fixed = re.sub(r'hashlib\.(md5|sha1)', 'hashlib.sha256', fixed, flags=re.IGNORECASE)
    return fixed, "Replace weak MD5/SHA1 with SHA-256 or SHA-512 for cryptographic hashing."


def _fix_ssl_verify(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'verify\s*=\s*False', 'verify=True', snippet, flags=re.IGNORECASE)
    fixed = re.sub(r'ssl\._create_unverified_context\s*\(\s*\)', 'ssl.create_default_context()', fixed)
    return fixed, "Enable SSL/TLS certificate verification to prevent man-in-the-middle attacks."


def _fix_debug_mode(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'DEBUG\s*=\s*True', 'DEBUG = False', snippet, flags=re.IGNORECASE)
    fixed = re.sub(r'debug\s*=\s*True', 'debug=False', fixed, flags=re.IGNORECASE)
    return fixed, "Disable debug mode in production to avoid exposing stack traces and sensitive data."


def _fix_insecure_deserialization(snippet: str) -> tuple[str, str]:
    if 'yaml' in snippet.lower():
        fixed = re.sub(r'yaml\.load\s*\(', 'yaml.safe_load(', snippet)
        return fixed, "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution."
    # pickle
    fixed = f"# UNSAFE: {snippet.strip()}\n# Use json.loads() or a safer serialization format instead"
    return fixed, "Avoid pickle for deserialization of untrusted data; use json.loads() or similar."


def _fix_jwt_none(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r"['\"]none['\"]", "'HS256'", snippet, flags=re.IGNORECASE)
    fixed = re.sub(r",?\s*['\"]none['\"]", "", fixed, flags=re.IGNORECASE)
    return fixed, "Remove 'none' from allowed JWT algorithms and require a keyed algorithm (HS256/RS256)."


def _fix_plaintext_password(snippet: str) -> tuple[str, str]:
    return (
        "if bcrypt.check_password_hash(stored_hash, provided_password):",
        "Use bcrypt.check_password_hash() to compare passwords instead of plaintext equality check.",
    )


def _fix_cors_wildcard(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r"\*", "https://yourdomain.com", snippet)
    return fixed, "Restrict CORS origins to specific trusted domains instead of using wildcard '*'."


def _fix_command_injection(snippet: str) -> tuple[str, str]:
    # os.system(cmd) → subprocess.run(shlex.split(cmd), check=True)
    if 'os.system' in snippet:
        fixed = re.sub(r'os\.system\s*\(([^)]+)\)', r'subprocess.run(shlex.split(\1), check=True)', snippet)
        return fixed, "Use subprocess.run() with a list of arguments instead of os.system() to prevent command injection."
    fixed = re.sub(r'shell\s*=\s*True', 'shell=False', snippet)
    return fixed, "Avoid shell=True in subprocess calls; pass command as a list to prevent injection."


def _fix_eval(snippet: str) -> tuple[str, str]:
    return (
        f"# UNSAFE: {snippet.strip()}\n# Avoid eval()/exec() — use ast.literal_eval() for data or a proper parser",
        "Replace eval()/exec() with ast.literal_eval() for safe literal evaluation, or redesign to avoid dynamic code execution.",
    )


def _fix_empty_except(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'except\s*:', 'except Exception as e:', snippet)
    return fixed, "Catch specific exception types and log them instead of silently ignoring all exceptions."


def _fix_secret_key(snippet: str) -> tuple[str, str]:
    match = re.match(r'(\s*)(SECRET_KEY|JWT_SECRET)\s*=\s*[\'"][^\'"]*[\'"]', snippet, re.IGNORECASE)
    if match:
        indent = match.group(1)
        var = match.group(2)
        return (
            f"{indent}{var} = os.environ.get('{var}', secrets.token_hex(32))",
            f"Generate a cryptographically strong secret key using secrets.token_hex(32) and load from environment.",
        )
    return (
        "import secrets\nSECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))",
        "Generate a cryptographically strong secret key and load from environment variable.",
    )


def _fix_ssti(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'render_template_string\s*\(', 'render_template(', snippet)
    return fixed, "Use render_template() with a static template file instead of render_template_string() to prevent SSTI."


def _fix_sensitive_print(snippet: str) -> tuple[str, str]:
    fixed = f"# REMOVED: {snippet.strip()}\n# Do not log sensitive values (passwords, tokens, keys)"
    return fixed, "Never log sensitive values; if debugging is needed, redact them (e.g. '[REDACTED]')."


def _fix_ssrf(snippet: str) -> tuple[str, str]:
    return (
        "# Validate URL against allowlist before making request\nALLOWED_HOSTS = ['api.example.com']\n"
        "if urlparse(user_url).hostname not in ALLOWED_HOSTS:\n    raise ValueError('URL not allowed')",
        "Validate user-supplied URLs against an allowlist of permitted hosts before making HTTP requests.",
    )


def _fix_route_no_auth(snippet: str) -> tuple[str, str]:
    return (
        "@app.route(...)\n@login_required\ndef view_function():",
        "Add @login_required (or equivalent) decorator to protect routes that require authentication.",
    )


# ── Bug fix templates ─────────────────────────────────────────────────────────

def _fix_bare_except(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'except\s*:', 'except Exception as e:', snippet)
    return fixed, "Catch specific exception types to avoid accidentally suppressing SystemExit or KeyboardInterrupt."


def _fix_mutable_default(snippet: str) -> tuple[str, str]:
    # def func(x, lst=[]) → def func(x, lst=None)  (body fix shown as comment)
    fixed = re.sub(r'=\s*\[\s*\]', '=None', snippet)
    fixed = re.sub(r'=\s*\{\s*\}', '=None', fixed)
    return (
        fixed + "\n    # Inside function body:\n    # if lst is None: lst = []",
        "Use None as default and initialise the mutable object inside the function body.",
    )


def _fix_division_zero(snippet: str) -> tuple[str, str]:
    return (
        f"if divisor != 0:\n    result = {snippet.strip()}\nelse:\n    result = 0  # or raise ValueError",
        "Guard division with a zero-check to prevent ZeroDivisionError at runtime.",
    )


def _fix_is_string(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'\bis\s+(["\'])', r'== \1', snippet)
    return fixed, "Use == for value equality comparison; 'is' checks object identity, which is unreliable for strings."


def _fix_missing_encoding(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'open\s*\(([^)]+)\)', lambda m: f"open({m.group(1)}, encoding='utf-8')"
                   if 'encoding' not in m.group(1) else m.group(0), snippet)
    return fixed, "Always specify encoding='utf-8' when opening text files to ensure consistent behaviour across platforms."


def _fix_type_coercion(snippet: str) -> tuple[str, str]:
    return (
        "try:\n    value = int(request.form['field'])\nexcept (ValueError, KeyError):\n    value = 0  # or return error response",
        "Wrap type coercion of user input in a try/except to handle invalid or missing values gracefully.",
    )


def _fix_os_popen(snippet: str) -> tuple[str, str]:
    fixed = re.sub(r'os\.popen\s*\(([^)]+)\)', r'subprocess.run(\1, shell=True, capture_output=True, text=True)', snippet)
    return fixed, "Replace deprecated os.popen() with subprocess.run() which provides better control and security."


def _fix_infinite_loop(snippet: str) -> tuple[str, str]:
    return (
        "while True:\n    # ... loop body ...\n    if <exit_condition>:\n        break",
        "Ensure the infinite loop has a reachable break or return statement to avoid hangs.",
    )


def _fix_ignored_return(snippet: str) -> tuple[str, str]:
    return (
        f"result = {snippet.strip().lstrip('_ =')}"
        if snippet.strip().startswith('_') else snippet,
        "Store or use the return value; if intentionally discarding, add a comment explaining why.",
    )


# ── Dispatch tables ───────────────────────────────────────────────────────────

_VULN_RULES: list[tuple[str, object]] = [
    ("sql injection - f-string",        _fix_sql_fstring),
    ("sql injection - percent",         _fix_sql_percent),
    ("sql injection - .format()",       _fix_sql_format),
    ("sql injection - concatenation",   _fix_sql_fstring),   # similar result
    ("weak hashing",                    _fix_weak_hash),
    ("hardcoded credential",            _fix_hardcoded_credential),
    ("hardcoded",                       _fix_hardcoded_credential),
    ("insecure deserialization",        _fix_insecure_deserialization),
    ("jwt with 'none'",                 _fix_jwt_none),
    ("jwt",                             _fix_jwt_none),
    ("plaintext password",              _fix_plaintext_password),
    ("ssl/tls certificate",             _fix_ssl_verify),
    ("ssl",                             _fix_ssl_verify),
    ("debug mode",                      _fix_debug_mode),
    ("command execution",               _fix_command_injection),
    ("command injection",               _fix_command_injection),
    ("cross-site scripting",            lambda s: (s, "Use textContent or innerText instead of innerHTML; sanitize user input before rendering.")),
    ("xss",                             lambda s: (s, "Sanitize all user-supplied data before inserting it into the DOM.")),
    ("server-side template injection",  _fix_ssti),
    ("ssti",                            _fix_ssti),
    ("overly permissive cors",          _fix_cors_wildcard),
    ("cors",                            _fix_cors_wildcard),
    ("dynamic code execution",          _fix_eval),
    ("eval",                            _fix_eval),
    ("weak or short secret key",        _fix_secret_key),
    ("secret key",                      _fix_secret_key),
    ("sensitive data logged",           _fix_sensitive_print),
    ("server-side request forgery",     _fix_ssrf),
    ("ssrf",                            _fix_ssrf),
    ("route handler without authentication", _fix_route_no_auth),
    ("empty exception handler",         _fix_empty_except),
]

_BUG_RULES: list[tuple[str, object]] = [
    ("bare except",                     _fix_bare_except),
    ("mutable default argument",        _fix_mutable_default),
    ("division by zero",                _fix_division_zero),
    ("identity comparison on string",   _fix_is_string),
    ("missing encoding",                _fix_missing_encoding),
    ("unguarded type coercion",         _fix_type_coercion),
    ("deprecated os.popen",             _fix_os_popen),
    ("potential infinite loop",         _fix_infinite_loop),
    ("ignored return value",            _fix_ignored_return),
    ("empty function body",             lambda s: (s.replace("pass", "raise NotImplementedError"), "Implement the function or raise NotImplementedError to signal it is intentionally unfinished.")),
    ("global variable mutation",        lambda s: (s, "Refactor to pass values as function parameters instead of mutating global state.")),
    ("unresolved todo",                 lambda s: (s, "Address or remove this TODO/FIXME before production release.")),
    ("re-raise without chaining",       lambda s: (re.sub(r'raise\s+(\w+)\s*\(([^)]*)\)\s*$', r'raise \1(\2) from err', s), "Chain exceptions with 'raise ... from err' to preserve the original traceback.")),
]


def generate_vuln_fix(title: str, code_snippet: str) -> tuple[str, str]:
    """Return (fixed_code, explanation) for a vulnerability finding.

    Tries each rule in order; falls back to a generic comment if nothing matches.
    """
    key = title.lower()
    for pattern, fn in _VULN_RULES:
        if pattern in key:
            try:
                return fn(code_snippet)  # type: ignore[operator]
            except Exception:
                break
    # Generic fallback
    return (
        f"# VULNERABLE: {code_snippet.strip()}\n# TODO: apply appropriate security fix — see description for guidance.",
        "Refer to the vulnerability description for specific remediation steps.",
    )


def generate_bug_fix(title: str, code_snippet: str) -> tuple[str, str]:
    """Return (fixed_code, explanation) for a bug finding.

    Tries each rule in order; falls back to a generic comment if nothing matches.
    """
    key = title.lower()
    for pattern, fn in _BUG_RULES:
        if pattern in key:
            try:
                return fn(code_snippet)  # type: ignore[operator]
            except Exception:
                break
    # Generic fallback
    return (
        f"# BUGGY: {code_snippet.strip()}\n# TODO: apply appropriate fix — see description for guidance.",
        "Refer to the bug description for specific remediation steps.",
    )
