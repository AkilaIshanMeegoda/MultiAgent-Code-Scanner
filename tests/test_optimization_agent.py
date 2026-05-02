"""
Tests for the OptimizationAdvisorAgent.

Validates that the optimization agent reads bugs from state (dependency),
and correctly populates state["optimizations"].
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.state import create_initial_state


class TestOptimizationState:
    """Tests for optimization state management."""

    def test_initial_state_has_optimizations_field(self) -> None:
        """State should have an empty optimizations list on init."""
        state = create_initial_state("/test", user_prompt="optimize")
        assert "optimizations" in state
        assert state["optimizations"] == []

    def test_state_preserves_optimizations(self) -> None:
        """Optimizations written to state should persist."""
        state = create_initial_state("/test", user_prompt="optimize")
        state["optimizations"] = [{"id": "OPT-0001", "title": "Cache result"}]
        assert len(state["optimizations"]) == 1
        assert state["optimizations"][0]["id"] == "OPT-0001"

    def test_optimization_can_read_bugs(self) -> None:
        """OptimizationAgent should be able to access bugs from state (dependency)."""
        state = create_initial_state("/test", user_prompt="optimize")
        state["bugs"] = [
            {"id": "BUG-0001", "title": "Bare except", "severity": "LOW"},
            {"id": "BUG-0002", "title": "Mutable default", "severity": "MEDIUM"},
        ]
        # Simulate what the optimization agent does: read bugs
        bugs = state.get("bugs", [])
        assert len(bugs) == 2
        assert bugs[0]["id"] == "BUG-0001"


class TestOptimizationAgentWithLLM:
    """Integration tests for OptimizationAdvisorAgent. Skipped if Ollama is not available."""

    @pytest.fixture(autouse=True)
    def check_ollama(self) -> None:
        """Skip tests if Ollama is not running."""
        try:
            import urllib.request
            req = urllib.request.Request("http://localhost:11434/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status != 200:
                    pytest.skip("Ollama not available")
        except Exception:
            pytest.skip("Ollama not available")

    def test_optimization_agent_returns_list(self) -> None:
        """OptimizationAgent should return a list of optimizations."""
        from src.agents.optimization_advisor import run_optimization_advisor_agent

        state = dict(create_initial_state("/test", user_prompt="optimize"))
        state["code_structure"] = {
            "file_contents": {
                "app.py": (
                    "data = []\n"
                    "for i in range(10000):\n"
                    "    data.append(i * 2)\n"
                    "result = sum(data)\n"
                ),
            },
            "languages": ["Python"],
            "file_list": ["app.py"],
            "total_lines": 4,
        }
        state["bugs"] = [{"id": "BUG-0001", "title": "Unused loop var", "severity": "LOW"}]

        result = run_optimization_advisor_agent(state)
        assert "optimizations" in result
        assert isinstance(result["optimizations"], list)

    def test_optimization_agent_handles_no_files(self) -> None:
        """OptimizationAgent should handle empty file contents gracefully."""
        from src.agents.optimization_advisor import run_optimization_advisor_agent

        state = dict(create_initial_state("/test", user_prompt="optimize"))
        state["code_structure"] = {"file_contents": {}}

        result = run_optimization_advisor_agent(state)
        assert result["optimizations"] == []
