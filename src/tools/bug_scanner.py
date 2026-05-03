"""
Bug Detection Tool

Scans source code for common bug patterns, logical errors, and runtime
risks using regex-based pattern matching.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import tool


# Bug patterns: (pattern, title, category, description, severity)
_BUG_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # Division by zero risks
    (r'\/\s*(?:int|float|len)\s*\(', "Potential Division by Zero",
     "Runtime Error", "Division using dynamic value without zero-check.", "MEDIUM"),
    # Bare except
    (r'except\s*:', "Bare Except Clause",
     "Error Handling", "Catches all exceptions including KeyboardInterrupt and SystemExit.", "LOW"),
    # Mutable default arguments
    (r'def\s+\w+\s*\([^)]*(?:=\s*\[\s*\]|=\s*\{\s*\})', "Mutable Default Argument",
     "Logical Error", "Using mutable default argument (list/dict); shared across calls.", "MEDIUM"),
    # Unused variable assignment (simple heuristic)
    (r'^\s+_\s*=\s*.+', "Ignored Return Value",
     "Code Quality", "Return value explicitly discarded; may indicate missed logic.", "LOW"),
    # Infinite loop risk
    (r'while\s+True\s*:', "Potential Infinite Loop",
     "Runtime Error", "while True without visible break may cause hangs.", "LOW"),
    # String comparison with is
    (r'\bis\s+"[^"]*"|\bis\s+\'[^"]*\'', "Identity Comparison on String Literal",
     "Logical Error", "Using 'is' instead of '==' for string comparison.", "MEDIUM"),
    # Hardcoded file paths
    (r'open\s*\(\s*["\']\/(?:tmp|etc|var)', "Hardcoded Absolute File Path",
     "Portability", "Hardcoded absolute path reduces cross-platform portability.", "LOW"),
    # Missing encoding in open()
    (r'open\s*\([^)]+\)\s*(?!.*encoding)', "Missing Encoding in open()",
     "Portability", "File opened without explicit encoding; behaviour varies across platforms.", "LOW"),
    # Broad type coercion
    (r'int\s*\(\s*request\.|float\s*\(\s*request\.', "Unguarded Type Coercion of User Input",
     "Runtime Error", "Type-casting user input without try/except may raise ValueError.", "MEDIUM"),
    # Deprecated function usage
    (r'os\.popen\s*\(', "Use of Deprecated os.popen",
     "Deprecation", "os.popen is deprecated; prefer subprocess module.", "LOW"),
    # Global variable mutation
    (r'^\s*global\s+\w+', "Global Variable Mutation",
     "Code Quality", "Mutating global state makes code harder to reason about.", "LOW"),
    # TODO/FIXME/HACK markers
    (r'#\s*(?:TODO|FIXME|HACK|XXX)\b', "Unresolved TODO/FIXME Marker",
     "Code Quality", "Code contains unresolved developer notes.", "LOW"),
]


@tool
def scan_code_for_bugs(file_contents: dict[str, str]) -> list[dict[str, Any]]:
    """Scan source code files for common bug patterns and logical errors.

    Args:
        file_contents: Mapping of file paths to their source code content.

    Returns:
        A list of detected bug dictionaries with id, title, category,
        description, file, line_number, code_snippet, and severity.
    """
    bugs: list[dict[str, Any]] = []
    bug_counter = 0

    for filepath, content in file_contents.items():
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for pattern, title, category, description, severity in _BUG_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    bug_counter += 1
                    bugs.append({
                        "id": f"BUG-{bug_counter:04d}",
                        "title": title,
                        "category": category,
                        "description": description,
                        "file": filepath,
                        "line_number": line_num,
                        "code_snippet": line.strip()[:200],
                        "severity": severity,
                    })

    return bugs
