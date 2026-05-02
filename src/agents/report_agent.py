"""
Agent 4: ReportAgent  (Member 4)

The final agent in the pipeline. Receives all findings from the three
specialist agents, correlates related issues (e.g. a bug that also causes
a vulnerability), prioritises by risk, and generates a professional
Markdown security report.

Outputs:
  - executive_summary: plain-language overview for stakeholders
  - full_report:       complete Markdown report saved to disk
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import get_model_name
from src.observability import AgentTracer
from src.tools.report_generator import generate_security_report

REPORT_AGENT_SYSTEM_PROMPT: str = """You are ReportAgent, a senior security consultant.

You receive all findings from three specialist agents and must produce a professional security report.

Your tasks:
1. Write a clear EXECUTIVE SUMMARY (2-3 paragraphs) for non-technical stakeholders.
   - Quantify risk: "X critical vulnerabilities, Y bugs, Z performance issues found."
   - Mention the most severe finding by name.
   - End with a clear recommended action (e.g. "Immediate patching required.").
2. Identify any CORRELATIONS: bugs that also introduce security risks, or optimisations that fix bugs too.
3. Write a FIX PRIORITY ROADMAP with 3 timeframes.

STRICT RULES:
- Reference actual file names and finding IDs.
- Be specific and concise — no generic filler text.
- Output must be valid JSON with NO markdown fences.

Output ONLY this JSON:
{
  "executive_summary": "2-3 paragraph summary...",
  "correlations": [
    "BUG-0003 and VULN-0001 share the same root cause in app.py:45 — fixing the bug also closes the vulnerability."
  ],
  "fix_priority_roadmap": "## Immediate (24-48 hours)\\n- Fix VULN-0001 SQL Injection in app.py\\n\\n## Short-term (1 week)\\n- Fix VULN-0003 Hardcoded credentials\\n\\n## Medium-term (1 month)\\n- Address BUG-0001 and OPT-0001"
}"""


def _severity_badge(severity: str) -> str:
    badges = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return badges.get(severity.upper(), severity)


def _parse_llm_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    return {}


def _build_fallback_summary(
    vulnerabilities: list[dict],
    bugs: list[dict],
    optimizations: list[dict],
) -> str:
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        s = v.get("severity", "MEDIUM").upper()
        if s in sev:
            sev[s] += 1
    parts = [
        f"Security audit identified {len(vulnerabilities)} vulnerability/vulnerabilities "
        f"(Critical: {sev['CRITICAL']}, High: {sev['HIGH']}, "
        f"Medium: {sev['MEDIUM']}, Low: {sev['LOW']})."
    ]
    if bugs:
        parts.append(f"{len(bugs)} code bug(s) were detected.")
    if optimizations:
        parts.append(f"{len(optimizations)} performance improvement(s) were suggested.")
    if sev["CRITICAL"] > 0 or sev["HIGH"] > 0:
        parts.append("Immediate remediation is required for critical and high severity findings.")
    return " ".join(parts)


def run_report_agent(state: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the ReportAgent.

    1. Collects all findings from VulnerabilityAgent and CodeQualityAgent.
    2. Calls the LLM to write an executive summary, correlations, and roadmap.
    3. Calls generate_security_report tool to build and save the Markdown report.

    Args:
        state: Global state with vulnerabilities, bugs, optimizations populated.

    Returns:
        State update with executive_summary and full_report.
    """
    tracer = AgentTracer("ReportAgent")

    vulnerabilities: list[dict[str, Any]] = state.get("vulnerabilities", [])
    bugs: list[dict[str, Any]]            = state.get("bugs", [])
    optimizations: list[dict[str, Any]]   = state.get("optimizations", [])
    project_path: str                      = state.get("project_path", ".")

    try:
        import datetime as _dt
        tracer.start("Generating final security report")

        # ── Step 1: LLM synthesis (optional — falls back gracefully) ──
        executive_summary: str = ""
        correlations: list[str] = []
        fix_roadmap: str = ""

        try:
            llm = ChatOllama(model=get_model_name(), temperature=0, num_predict=512, num_ctx=4096)

            vuln_summary = json.dumps(
                [{"id": v.get("id"), "title": v.get("title"),
                  "severity": v.get("severity"), "file": v.get("file")}
                 for v in vulnerabilities[:10]],
                indent=2,
            )
            bug_summary = json.dumps(
                [{"id": b.get("id"), "title": b.get("title"),
                  "severity": b.get("severity"), "file": b.get("file")}
                 for b in bugs[:5]],
                indent=2,
            )

            prompt = (
                f"VULNERABILITIES ({len(vulnerabilities)}):\n{vuln_summary}\n\n"
                f"BUGS ({len(bugs)}):\n{bug_summary}\n\n"
                "Write the executive summary, identify correlations, and create the fix priority roadmap."
            )

            response = llm.invoke([
                SystemMessage(content=REPORT_AGENT_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
            tracer.log_tool_call(
                f"LLM ({get_model_name()})",
                f"Synthesising {len(vulnerabilities)} vulns + {len(bugs)} bugs",
                f"Response length: {len(response.content)} chars",
            )
            llm_result = _parse_llm_json(response.content)
            executive_summary = llm_result.get("executive_summary", "")
            correlations      = llm_result.get("correlations", [])
            fix_roadmap       = llm_result.get("fix_priority_roadmap", "")

        except Exception as llm_exc:
            tracer.log_tool_call(
                f"LLM ({get_model_name()})",
                "Executive summary synthesis",
                f"SKIPPED — LLM error: {llm_exc}",
            )

        # Always use fallback summary if LLM didn't produce one
        if not executive_summary:
            executive_summary = _build_fallback_summary(vulnerabilities, bugs, optimizations)

        # ── Step 2: Generate & save Markdown report (Tool) ─────────
        report_result: dict[str, Any] = generate_security_report.invoke({
            "project_path": project_path,
            "executive_summary": executive_summary,
            "vulnerabilities": vulnerabilities,
            "exploitability_assessments": [],
            "remediation_snippets": {},
            "fix_priority_roadmap": fix_roadmap,
            "bugs": bugs,
            "optimizations": optimizations,
        })
        tracer.log_tool_call(
            "generate_security_report",
            f"Building report for {len(vulnerabilities)} vulns",
            f"Saved to: {report_result.get('report_path', 'unknown')}",
        )

        full_report: str = report_result.get("report_content", "")

        if correlations:
            corr_section = "\n\n---\n## Finding Correlations\n\n"
            corr_section += "\n".join(f"- {c}" for c in correlations)
            full_report += corr_section

        trace = tracer.complete(
            f"Report generated | {len(full_report)} chars | "
            f"Saved: {report_result.get('report_path', '')}"
        )

        return {
            "executive_summary": executive_summary,
            "full_report": full_report,
            "completed_at": _dt.datetime.now().isoformat(),
            "status": "complete",
            "current_agent": "ReportAgent",
            "agent_traces": [trace],
        }

    except Exception as exc:
        import datetime as _dt
        trace = tracer.error(str(exc))
        fallback = _build_fallback_summary(vulnerabilities, bugs, optimizations)
        # Still try to generate the report with what we have
        try:
            report_result = generate_security_report.invoke({
                "project_path": project_path,
                "executive_summary": fallback,
                "vulnerabilities": vulnerabilities,
                "exploitability_assessments": [],
                "remediation_snippets": {},
                "fix_priority_roadmap": "",
                "bugs": bugs,
                "optimizations": optimizations,
            })
            full_report = report_result.get("report_content", "")
        except Exception:
            full_report = f"# Security Audit Report\n\n{fallback}"
        return {
            "executive_summary": fallback,
            "full_report": full_report,
            "completed_at": _dt.datetime.now().isoformat(),
            "status": "complete",
            "current_agent": "ReportAgent",
            "agent_traces": [trace],
        }
