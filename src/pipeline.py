"""
LangGraph Pipeline - 4-Agent Code Security Auditor.

Architecture:
  START -> orchestrator -> vulnerability_agent ->
           code_quality_agent -> report_agent -> END

The two scanner agents (VulnerabilityAgent, CodeQualityAgent) run
SEQUENTIALLY after the Orchestrator and feed results into the final
ReportAgent.  If either scanner errors out, we route to handle_error.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph

from src.agents.orchestrator import run_orchestrator_agent
from src.agents.vulnerability_agent import run_vulnerability_agent
from src.agents.code_quality_agent import run_code_quality_agent
from src.agents.report_agent import run_report_agent
from src.observability import console, logger, print_pipeline_summary
from src.state import create_initial_state


class PipelineState(TypedDict, total=False):
    """LangGraph-compatible state with reducer for agent_traces."""

    # Core identifiers
    session_id: str
    project_path: str
    user_prompt: str
    started_at: str
    completed_at: str
    status: str
    current_agent: str
    scan_scope: str          # 'security' | 'quality' | 'full'

    # Agent outputs
    code_context: dict      # OrchestratorAgent
    code_structure: dict    # alias kept for backward-compat with frontend
    vulnerabilities: list
    severity_summary: dict
    bugs: list
    optimizations: list
    executive_summary: str
    full_report: str

    # Accumulated traces — operator.add merges lists across parallel nodes
    agent_traces: Annotated[list, operator.add]


# -- Routing helpers ---------------------------------------------------------

def _after_orchestrator(state: PipelineState) -> str:
    """Decide which scanner agent to run first.

    Routing table
    ─────────────────────────────────────────────────────────────────
    scan_scope == "security"  → vulnerability_agent  (then report)
    scan_scope == "quality"   → code_quality_agent   (then report)
    scan_scope == "full"      → vulnerability_agent  (then code_quality → report)
    no files found            → report_agent          (nothing to scan)
    error                     → handle_error
    ─────────────────────────────────────────────────────────────────
    scan_scope is set deterministically by the keyword classifier in
    orchestrator.py — it does NOT come from the LLM.
    """
    if state.get("status") == "error":
        return "handle_error"

    files = state.get("code_context", {}).get("files", {})
    if not files:
        logger.warning("No source files found — routing straight to report.")
        return "report_agent"

    scope = state.get("scan_scope", "full")

    if scope == "quality":
        # User asked about bugs/optimizations only — skip vulnerability scan
        return "code_quality_agent"

    # "security" or "full" — always start with vulnerability scan
    return "vulnerability_agent"


def _after_vulnerability(state: PipelineState) -> str:
    """After vulnerability scan: run code-quality or go straight to report.

    Routing table
    ─────────────────────────────────────────────────────────────────
    scan_scope == "security"  → report_agent         (skip code quality)
    scan_scope == "full"      → code_quality_agent
    error                     → handle_error
    ─────────────────────────────────────────────────────────────────
    """
    if state.get("status") == "error":
        return "handle_error"

    scope = state.get("scan_scope", "full")

    if scope == "security":
        # Security-only run — code quality not requested
        return "report_agent"

    # "full" — continue to code quality scan
    return "code_quality_agent"


def _after_code_quality(state: PipelineState) -> str:
    if state.get("status") == "error":
        return "handle_error"
    return "report_agent"


def _handle_error(state: PipelineState) -> dict[str, Any]:
    logger.error(f"Pipeline error at: {state.get('current_agent', 'unknown')}")
    return {
        "status": "completed_with_errors",
        "completed_at": __import__("datetime").datetime.now().isoformat(),
    }


# -- Pipeline builder --------------------------------------------------------

def build_pipeline():
    """Build and compile the 4-agent LangGraph pipeline.

    Returns:
        Compiled LangGraph StateGraph.
    """
    wf = StateGraph(PipelineState)

    # Nodes
    wf.add_node("orchestrator",        run_orchestrator_agent)
    wf.add_node("vulnerability_agent", run_vulnerability_agent)
    wf.add_node("code_quality_agent",  run_code_quality_agent)
    wf.add_node("report_agent",        run_report_agent)
    wf.add_node("handle_error",        _handle_error)

    # Entry
    wf.set_entry_point("orchestrator")

    # Orchestrator → vulnerability_agent (security/full) or code_quality_agent (quality/perf)
    wf.add_conditional_edges(
        "orchestrator",
        _after_orchestrator,
        {
            "vulnerability_agent": "vulnerability_agent",
            "code_quality_agent":  "code_quality_agent",   # quality/performance scope
            "report_agent":        "report_agent",
            "handle_error":        "handle_error",
        },
    )

    # VulnerabilityAgent → code_quality_agent (full) or report_agent (security-only)
    wf.add_conditional_edges(
        "vulnerability_agent",
        _after_vulnerability,
        {
            "code_quality_agent": "code_quality_agent",
            "report_agent":       "report_agent",           # security-only scope
            "handle_error":       "handle_error",
        },
    )

    # CodeQualityAgent ? report_agent (or error)
    wf.add_conditional_edges(
        "code_quality_agent",
        _after_code_quality,
        {
            "report_agent": "report_agent",
            "handle_error": "handle_error",
        },
    )

    # Terminal edges
    wf.add_edge("report_agent",  END)
    wf.add_edge("handle_error",  END)

    return wf.compile()


# -- Main entry point --------------------------------------------------------

def run_security_audit(
    project_path: str,
    user_prompt: str = "",
) -> dict[str, Any]:
    """Execute a complete security audit on a project.

    Initialises state, runs the 4-agent pipeline, and returns the final
    state containing all findings and the generated report.

    Args:
        project_path: Absolute path to the project directory to audit.
        user_prompt:  Natural-language description of what the user wants.

    Returns:
        Final state dict with all agent outputs and the generated report.
    """
    console.print("\n" + "-" * 70)
    console.print("[bold magenta]??  CODE SECURITY AUDITOR  ·  4-Agent LangGraph Pipeline[/bold magenta]")
    console.print("-" * 70)
    console.print(f"[dim]  Target : {project_path}[/dim]")
    if user_prompt:
        console.print(f"[dim]  Prompt : {user_prompt[:120]}[/dim]")
    console.print()

    # -- Visual topology ----------------------------------------------------
    console.print("[bold cyan]  +--------------------------------------------------+[/bold cyan]")
    console.print("[bold cyan]  ¦         4-AGENT PIPELINE TOPOLOGY               ¦[/bold cyan]")
    console.print("[bold cyan]  ¦--------------------------------------------------¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]                                                  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold white]+--------------------+[/bold white]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold white]¦  OrchestratorAgent ¦[/bold white]  Member 1  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold white]+--------------------+[/bold white]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]                 [bold yellow]?[/bold yellow]                         [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]+--------------------+[/bold red]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]¦ VulnerabilityAgent ¦[/bold red]  Member 2  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]+--------------------+[/bold red]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]                 [bold yellow]?[/bold yellow]                         [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]+--------------------+[/bold red]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]¦  CodeQualityAgent  ¦[/bold red]  Member 3  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold red]+--------------------+[/bold red]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]                 [bold yellow]?[/bold yellow]                         [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold green]+--------------------+[/bold green]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold green]¦    ReportAgent     ¦[/bold green]  Member 4  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]       [bold green]+--------------------+[/bold green]           [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  ¦[/bold cyan]                                                  [bold cyan]¦[/bold cyan]")
    console.print("[bold cyan]  +--------------------------------------------------+[/bold cyan]")
    console.print()

    # -- State initialisation ----------------------------------------------
    initial_state = dict(create_initial_state(project_path, user_prompt))
    initial_state["agent_traces"] = []

    logger.info(
        f"Starting security audit | Session: {initial_state['session_id']} | "
        f"Target: {project_path} | Prompt: {user_prompt[:80]}"
    )

    # -- Build & run --------------------------------------------------------
    pipeline = build_pipeline()

    console.print("[bold blue]??  LangGraph Node/Edge Topology:[/bold blue]")
    try:
        graph = pipeline.get_graph()
        node_names = [n for n in graph.nodes if n not in ("__start__", "__end__")]
        console.print(f"[dim]  Nodes : {', '.join(node_names)}[/dim]")
        for edge in graph.edges:
            src = "START" if edge.source == "__start__" else edge.source
            tgt = "END"   if edge.target == "__end__"   else edge.target
            console.print(f"[dim]  Edge  : {src} ? {tgt}[/dim]")
    except Exception:
        pass

    console.print("\n[bold blue]?? LangGraph Streaming Execution:[/bold blue]\n")
    final_state = dict(initial_state)
    node_order: list[str] = []

    for step in pipeline.stream(initial_state, stream_mode="updates"):
        for node_name, node_output in step.items():
            node_order.append(node_name)
            is_error = isinstance(node_output, dict) and node_output.get("status") == "error"
            icon = "?" if is_error else "?"
            console.print(
                f"[bold blue]  [LangGraph][/bold blue] {icon} "
                f"Node [cyan]{node_name!r}[/cyan] completed"
            )
            if isinstance(node_output, dict):
                for key, val in node_output.items():
                    if key == "agent_traces":
                        final_state.setdefault("agent_traces", [])
                        if isinstance(val, list):
                            final_state["agent_traces"].extend(val)
                    else:
                        final_state[key] = val

    if node_order:
        console.print(
            f"\n[bold blue]  [LangGraph][/bold blue] "
            f"Execution path: {' ? '.join(node_order)}\n"
        )

    print_pipeline_summary(final_state)

    if final_state.get("full_report"):
        console.print("\n[bold green]? Security audit complete![/bold green]")
        console.print(f"[dim]Session ID: {final_state.get('session_id')}[/dim]")
    else:
        console.print("\n[bold yellow]?? Audit completed with issues.[/bold yellow]")

    return final_state

