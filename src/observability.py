"""
Observability & Logging Module for the Code Security Auditor MAS.

Implements structured logging with execution tracing for every agent interaction,
tool call, and state transition. Provides AgentOps-style observability
as required by the assignment specification.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any

import io
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Rich console — configured for safe operation on Windows (no legacy renderer,
# no emoji encoding failures, UTF-8 with replacement for unencodable chars).
try:
    if hasattr(sys.stdout, 'buffer'):
        _safe_stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True
        )
    else:
        _safe_stdout = sys.stdout
except Exception:
    _safe_stdout = sys.stdout

console = Console(
    file=_safe_stdout,
    legacy_windows=False,
    safe_box=True,
    highlight=False,
)


def _safe_print(*args, **kwargs) -> None:
    """Print via Rich console, silently ignoring any encoding/render errors."""
    try:
        console.print(*args, **kwargs)
    except Exception:
        pass

# Configure structured logger
LOG_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_file: str = os.path.join(LOG_DIR, f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

logger: logging.Logger = logging.getLogger("CodeSecurityAuditor")


class AgentTracer:
    """
    Traces agent executions with detailed timing, inputs, outputs, and tool calls.
    
    Provides structured observability data for each agent in the pipeline,
    recording all interactions for debugging and audit purposes.
    """

    def __init__(self, agent_name: str) -> None:
        """Initialize a tracer for a specific agent.

        Args:
            agent_name: The name of the agent being traced.
        """
        self.agent_name: str = agent_name
        self.start_time: float = 0.0
        self.tool_calls: list[dict[str, Any]] = []
        self.trace_file: str = os.path.join(
            LOG_DIR,
            f"trace_{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )

    def start(self, input_summary: str) -> None:
        """Begin tracing an agent execution.

        Args:
            input_summary: Summary of the input data for this execution.
        """
        self.start_time = time.time()
        self.tool_calls = []
        logger.info(f"[{self.agent_name}] STARTED | Input: {input_summary[:200]}")
        _safe_print(Panel(
            f"[bold cyan]Agent: {self.agent_name}[/bold cyan]\n"
            f"Input: {input_summary[:150]}",
            title=">> Agent Started",
            border_style="cyan",
        ))

    def log_tool_call(self, tool_name: str, tool_input: str, tool_output: str) -> None:
        """Record a tool invocation within this agent's execution.

        Args:
            tool_name: Name of the tool that was called.
            tool_input: Summary of the input passed to the tool.
            tool_output: Summary of the output returned by the tool.
        """
        call_record: dict[str, Any] = {
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "input_summary": tool_input[:300],
            "output_summary": tool_output[:300],
        }
        self.tool_calls.append(call_record)
        logger.info(f"[{self.agent_name}] TOOL_CALL | {tool_name} | Input: {tool_input[:100]}")

    def complete(self, output_summary: str, status: str = "success") -> dict[str, Any]:
        """Finalize tracing for this agent execution.

        Args:
            output_summary: Summary of the agent's output.
            status: Completion status (success/error).

        Returns:
            A trace dictionary with all recorded data.
        """
        duration: float = round(time.time() - self.start_time, 2)
        trace: dict[str, Any] = {
            "agent_name": self.agent_name,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "input_summary": "",
            "output_summary": output_summary[:500],
            "tool_calls": self.tool_calls,
            "status": status,
            "error": None,
        }

        # Save individual trace
        with open(self.trace_file, "w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, default=str)

        logger.info(
            f"[{self.agent_name}] COMPLETED | Duration: {duration}s | "
            f"Tools used: {len(self.tool_calls)} | Status: {status}"
        )

        severity_color = "green" if status == "success" else "red"
        title = "[OK] Agent Completed" if status == "success" else "[ERR] Agent Failed"
        _safe_print(Panel(
            f"[bold {severity_color}]Agent: {self.agent_name}[/bold {severity_color}]\n"
            f"Duration: {duration}s | Tools: {len(self.tool_calls)}\n"
            f"Output: {output_summary[:150]}",
            title=title,
            border_style=severity_color,
        ))

        return trace

    def error(self, error_msg: str) -> dict[str, Any]:
        """Record an error during agent execution.

        Args:
            error_msg: The error message.

        Returns:
            A trace dictionary with error information.
        """
        logger.error(f"[{self.agent_name}] ERROR | {error_msg}")
        return self.complete(f"Error: {error_msg}", status="error")


def print_state_transition(from_agent: str, to_agent: str, state_keys: list[str]) -> None:
    """Log and display a state transition between agents.

    Args:
        from_agent: The agent passing state.
        to_agent: The agent receiving state.
        state_keys: Keys being passed in the state.
    """
    logger.info(f"STATE_TRANSITION | {from_agent} -> {to_agent} | Keys: {state_keys}")
    _safe_print(
        f"  [dim]State passed: {from_agent} -> {to_agent} | "
        f"Keys: {', '.join(state_keys)}[/dim]"
    )


def print_pipeline_summary(state: dict[str, Any]) -> None:
    """Print a final summary table of the entire pipeline execution.

    Args:
        state: The final global state after all agents have run.
    """
    table = Table(title="Pipeline Execution Summary")
    table.add_column("Agent", style="cyan", justify="left")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Duration", style="yellow", justify="right")
    table.add_column("Tool Calls", style="magenta", justify="right")

    traces: list[dict[str, Any]] = state.get("agent_traces", [])
    for trace in traces:
        status_icon = "[OK]" if trace.get("status") == "success" else "[ERR]"
        table.add_row(
            trace.get("agent_name", "Unknown"),
            f"{status_icon} {trace.get('status', 'unknown')}",
            f"{trace.get('duration_seconds', 0)}s",
            str(len(trace.get("tool_calls", []))),
        )

    _safe_print(table)

    # Print vulnerability summary
    vulns: list[dict[str, Any]] = state.get("vulnerabilities", [])
    if vulns:
        vuln_table = Table(title="Vulnerability Summary")
        vuln_table.add_column("Severity", justify="center")
        vuln_table.add_column("Count", justify="center")

        counts: dict[str, int] = {}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in counts:
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}.get(sev, "white")
                vuln_table.add_row(f"[{color}]{sev}[/{color}]", str(counts[sev]))

        _safe_print(vuln_table)
