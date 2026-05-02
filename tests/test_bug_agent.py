"""
Tests for the BugDetectorAgent and its bug_scanner tool.

Validates that the bug scanner detects common bug patterns and
that the agent properly populates state["bugs"].
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.bug_scanner import scan_code_for_bugs
from src.state import create_initial_state


SAMPLE_APP_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_vulnerable_app",
)


class TestBugScannerTool:
    """Tests for the bug_scanner tool."""

    def test_detects_bare_except(self) -> None:
        """Should detect bare except clauses."""
        code = {"app.py": "try:\n    x = 1\nexcept:\n    pass"}
        result = scan_code_for_bugs.invoke({"file_contents": code})
        titles = [b["title"] for b in result]
        assert any("Bare Except" in t for t in titles)

    def test_detects_mutable_default(self) -> None:
        """Should detect mutable default arguments."""
        code = {"app.py": "def add_item(item, items=[]):\n    items.append(item)"}
        result = scan_code_for_bugs.invoke({"file_contents": code})
        titles = [b["title"] for b in result]
        assert any("Mutable Default" in t for t in titles)

    def test_returns_proper_structure(self) -> None:
        """Each bug should have required fields."""
        code = {"app.py": "try:\n    x = 1\nexcept:\n    pass"}
        result = scan_code_for_bugs.invoke({"file_contents": code})
        for bug in result:
            assert "id" in bug
            assert "title" in bug
            assert "severity" in bug
            assert "file" in bug
            assert "line_number" in bug
            assert bug["severity"] in ("HIGH", "MEDIUM", "LOW")

    def test_no_bugs_in_clean_code(self) -> None:
        """Should not flag obviously clean code."""
        clean = {"clean.py": "def add(a, b):\n    return a + b\n\nresult = add(1, 2)\n"}
        result = scan_code_for_bugs.invoke({"file_contents": clean})
        assert len(result) == 0

    def test_bug_ids_are_unique(self) -> None:
        """Bug IDs should be unique across all findings."""
        code = {
            "a.py": "try:\n    pass\nexcept:\n    pass\n",
            "b.py": "def f(x=[]):\n    return x\n",
        }
        result = scan_code_for_bugs.invoke({"file_contents": code})
        ids = [b["id"] for b in result]
        assert len(ids) == len(set(ids))

    def test_detects_deprecated_os_popen(self) -> None:
        """Should detect os.popen usage."""
        code = {"app.py": "import os\nresult = os.popen('ls')"}
        result = scan_code_for_bugs.invoke({"file_contents": code})
        titles = [b["title"] for b in result]
        assert any("os.popen" in t for t in titles)


class TestBugDetectorState:
    """Tests for bug state management."""

    def test_initial_state_has_bugs_field(self) -> None:
        """State should have an empty bugs list on init."""
        state = create_initial_state("/test", user_prompt="find bugs")
        assert "bugs" in state
        assert state["bugs"] == []

    def test_state_preserves_bugs(self) -> None:
        """Bugs written to state should persist."""
        state = create_initial_state("/test", user_prompt="find bugs")
        state["bugs"] = [{"id": "BUG-0001", "title": "Test bug"}]
        assert len(state["bugs"]) == 1
        assert state["bugs"][0]["id"] == "BUG-0001"
