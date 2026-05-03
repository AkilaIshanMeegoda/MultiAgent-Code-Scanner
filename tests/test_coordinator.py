"""
Tests for the CoordinatorAgent.

Validates that the coordinator correctly selects agents based on
user prompts and file availability.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.state import create_initial_state


class TestCoordinatorAgentSelection:
    """Tests for coordinator agent selection logic (no LLM required)."""

    def test_state_includes_user_prompt(self) -> None:
        """Initial state should preserve the user prompt."""
        state = create_initial_state("/test/path", user_prompt="find security issues")
        assert state["user_prompt"] == "find security issues"

    def test_state_has_files_true(self) -> None:
        """has_files should be True when a project path is provided."""
        state = create_initial_state("/test/path", user_prompt="audit")
        assert state["has_files"] is True

    def test_state_has_files_false_when_empty(self) -> None:
        """has_files should be False when project path is empty string."""
        state = create_initial_state("", user_prompt="audit")
        assert state["has_files"] is False

    def test_selected_agents_initially_empty(self) -> None:
        """selected_agents should start as an empty list."""
        state = create_initial_state("/test", user_prompt="audit")
        assert state["selected_agents"] == []

    def test_coordinator_reasoning_initially_empty(self) -> None:
        """coordinator_reasoning should start as empty string."""
        state = create_initial_state("/test", user_prompt="audit")
        assert state["coordinator_reasoning"] == ""


class TestCoordinatorAgentWithLLM:
    """Integration tests for CoordinatorAgent. Skipped if Ollama is not available."""

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

    def test_coordinator_selects_agents(self) -> None:
        """Coordinator should select at least one agent when files exist."""
        from src.agents.coordinator import run_coordinator_agent

        state = dict(create_initial_state("/test/path", user_prompt="Perform a full security audit"))
        result = run_coordinator_agent(state)
        assert "selected_agents" in result
        assert isinstance(result["selected_agents"], list)
        assert len(result["selected_agents"]) > 0

    def test_coordinator_returns_reasoning(self) -> None:
        """Coordinator should provide a reason for its selection."""
        from src.agents.coordinator import run_coordinator_agent

        state = dict(create_initial_state("/test/path", user_prompt="Find bugs in my code"))
        result = run_coordinator_agent(state)
        assert "coordinator_reasoning" in result
        assert len(result["coordinator_reasoning"]) > 0

    def test_coordinator_selects_vuln_for_security_prompt(self) -> None:
        """Coordinator should select vulnerability_detector for security-related prompts."""
        from src.agents.coordinator import run_coordinator_agent

        state = dict(create_initial_state("/test/path", user_prompt="Check for security vulnerabilities"))
        result = run_coordinator_agent(state)
        assert "vulnerability_detector" in result["selected_agents"]

    def test_coordinator_valid_agent_names(self) -> None:
        """All selected agents should be from the valid set."""
        from src.agents.coordinator import run_coordinator_agent, VALID_AGENTS

        state = dict(create_initial_state("/test/path", user_prompt="Full analysis"))
        result = run_coordinator_agent(state)
        for agent in result["selected_agents"]:
            assert agent in VALID_AGENTS, f"Invalid agent name: {agent}"
