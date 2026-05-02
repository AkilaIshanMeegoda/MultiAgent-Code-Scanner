"""
Tool 1: Source Code File Reader & Analyzer

This tool reads source code files from a local project directory,
identifies programming languages, and extracts structural metadata.
Used by the CodeScannerAgent to gather raw code data for analysis.

Author: Student 1 (CodeScannerAgent owner)
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.tools import tool

# Supported source code file extensions and their language mappings
LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".html": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
    ".sh": "Shell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".env": "Environment",
    ".toml": "TOML",
    ".cfg": "Config",
    ".ini": "Config",
}

# Directories to skip during scanning
SKIP_DIRS: set[str] = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".idea", ".vscode",
    ".mypy_cache", ".pytest_cache", "eggs", "*.egg-info",
    ".tox", "htmlcov", ".coverage",
}

# Maximum file size to read (500KB)
MAX_FILE_SIZE: int = 512_000


@tool
def read_project_files(project_path: str) -> dict[str, Any]:
    """Read all source code files from a local project directory and return their contents with metadata.

    This tool scans a project directory recursively, identifies programming languages
    based on file extensions, reads file contents, and returns structured metadata
    including language distribution, file list, and total line counts.

    Args:
        project_path: The absolute path to the project directory to scan.

    Returns:
        A dictionary containing:
            - languages: List of detected programming languages
            - file_list: List of all scanned file paths (relative)
            - file_contents: Dict mapping relative file paths to their source code
            - total_lines: Total number of lines across all files
            - language_distribution: Dict mapping languages to file counts
            - errors: List of any files that could not be read
    """
    if not os.path.isdir(project_path):
        return {"error": f"Directory not found: {project_path}"}

    file_contents: dict[str, str] = {}
    file_list: list[str] = []
    language_counts: dict[str, int] = {}
    total_lines: int = 0
    errors: list[str] = []

    for root, dirs, files in os.walk(project_path):
        # Filter out directories we want to skip
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath: str = os.path.join(root, filename)
            rel_path: str = os.path.relpath(filepath, project_path)
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            if ext not in LANGUAGE_MAP:
                continue

            language: str = LANGUAGE_MAP[ext]

            try:
                file_size: int = os.path.getsize(filepath)
                if file_size > MAX_FILE_SIZE:
                    errors.append(f"Skipped (too large): {rel_path}")
                    continue

                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content: str = f.read()

                file_contents[rel_path] = content
                file_list.append(rel_path)
                line_count: int = content.count("\n") + 1
                total_lines += line_count
                language_counts[language] = language_counts.get(language, 0) + 1

            except (OSError, PermissionError) as exc:
                errors.append(f"Error reading {rel_path}: {str(exc)}")

    languages: list[str] = list(language_counts.keys())

    return {
        "languages": languages,
        "file_list": file_list,
        "file_contents": file_contents,
        "total_lines": total_lines,
        "language_distribution": language_counts,
        "errors": errors,
    }
