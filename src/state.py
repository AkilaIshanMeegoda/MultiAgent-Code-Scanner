"""
Global State Management for the Code Security Auditor MAS.

4-Agent Architecture:
  1. OrchestratorAgent  - reads files, detects languages/frameworks, sets scan scope
  2. VulnerabilityAgent - OWASP Top 10 detection with fix suggestions
  3. CodeQualityAgent   - bug detection + performance optimizations with fix suggestions
  4. ReportAgent        - correlates findings, generates final Markdown report

State flows through all agents; each agent writes only its own keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, TypedDict


class AgentTrace(TypedDict, total=False):
    """Represents a single agent execution trace for observability."""
    agent_name: str
    timestamp: str
    input_summary: str
    output_summary: str
    tool_calls: list[dict[str, Any]]
    tool_calls_count: int
    duration_seconds: float
    status: str
    error: str | None


class GlobalState(TypedDict, total=False):
    """
    The global state that flows through the entire 4-agent pipeline.

    Each agent reads from the accumulated state and returns only the keys it owns.
    agent_traces uses an operator.add reducer to accumulate across all agents.
    """
    # Session metadata
    session_id: str
    project_path: str
    user_prompt: str
    started_at: str
    completed_at: str
    status: str
    current_agent: str

    # Agent 1: OrchestratorAgent
    # code_context: {files, languages, frameworks, entry_points, data_flows,
    #                scan_scope, file_count, total_lines}
    code_context: dict[str, Any]
    code_structure: dict[str, Any]   # alias for frontend backward compat

    # Agent 2: VulnerabilityAgent
    # Each finding: {id, title, category, owasp_category, description,
    #   file, line_number, code_snippet, severity, cvss_score,
    #   current_code, fixed_code, fix_explanation}
    vulnerabilities: list[dict[str, Any]]
    severity_summary: dict[str, int]

    # Agent 3: CodeQualityAgent
    # bugs: {id, title, category, description, file, line_number,
    #   code_snippet, severity, current_code, fixed_code, fix_explanation}
    bugs: list[dict[str, Any]]
    # optimizations: same shape, uses priority instead of severity
    optimizations: list[dict[str, Any]]

    # Agent 4: ReportAgent
    executive_summary: str
    full_report: str

    # Observability (accumulated via operator.add reducer in pipeline)
    agent_traces: list[AgentTrace]


def create_initial_state(project_path: str, user_prompt: str = "") -> GlobalState:
    """Create a fresh initial state for a new security audit session."""
    return GlobalState(
        session_id=str(uuid.uuid4()),
        project_path=project_path,
        user_prompt=user_prompt,
        started_at=datetime.now().isoformat(),
        completed_at="",
        status="initialized",
        current_agent="",
        code_context={},
        code_structure={},
        vulnerabilities=[],
        severity_summary={},
        bugs=[],
        optimizations=[],
        executive_summary="",
        full_report="",
        agent_traces=[],
    )
