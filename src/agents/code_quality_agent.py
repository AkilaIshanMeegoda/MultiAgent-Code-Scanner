"""
Agent 3: CodeQualityAgent  (Member 3)

Combines bug detection and performance optimisation into a single agent.
Uses the scan_code_for_bugs tool for automated detection, then the LLM
validates and produces fix suggestions.

For every confirmed finding the LLM produces:
  - current_code   : the actual buggy/inefficient code
  - fixed_code     : the corrected replacement
  - fix_explanation: concise explanation of what changed and why

Outputs:
  - bugs:          list of bug dicts  (type = "bug")
  - optimizations: list of opt dicts  (type = "optimization")
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import get_model_name
from src.observability import AgentTracer
from src.tools.bug_scanner import scan_code_for_bugs
from src.tools.pattern_fixes import generate_bug_fix

CODE_FIX_SYSTEM_PROMPT: str = """You are a senior software engineer. For each buggy or inefficient code line, write the fixed version.

RULES:
- fixed_code: write ONLY the fixed replacement line(s) for the buggy code
- fix_explanation: ONE sentence explaining what changed and why
- Keep fixes minimal — change as little code as possible
- Output ONLY valid JSON, no markdown fences, no extra text

Output ONLY this JSON (preserve the exact IDs given to you):
{"fixes": [{"id": "BUG-0001", "fixed_code": "except ValueError as e:\\n    logger.error(f'Error: {e}')", "fix_explanation": "Catch specific exception type instead of bare except to avoid swallowing system exits."}]}"""


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


def run_code_quality_agent(state: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the CodeQualityAgent.

    1. Runs scan_code_for_bugs tool on all project files.
    2. Sends tool results and code context to LLM for validation and enrichment.
    3. Returns bugs and optimizations, each with current_code / fixed_code / fix_explanation.

    Args:
        state: Global state with code_context populated by OrchestratorAgent.

    Returns:
        State update with bugs and optimizations lists.
    """
    tracer = AgentTracer("CodeQualityAgent")

    try:
        tracer.start("Scanning for bugs and performance issues")
        file_contents: dict[str, str] = state.get("code_context", {}).get("files", {})

        if not file_contents:
            trace = tracer.complete("No files available — skipping.")
            return {
                "bugs": [],
                "optimizations": [],
                "current_agent": "CodeQualityAgent",
                "agent_traces": [trace],
            }

        tool_bugs: list[dict[str, Any]] = scan_code_for_bugs.invoke(
            {"file_contents": file_contents}
        )
        tracer.log_tool_call(
            "scan_code_for_bugs",
            f"Scanning {len(file_contents)} files",
            f"Found {len(tool_bugs)} potential bugs",
        )

        for bug in tool_bugs:
            bug.setdefault("type", "bug")
            bug.setdefault("current_code", bug.get("code_snippet", ""))
            bug.setdefault("fixed_code", "")
            bug.setdefault("fix_explanation", "")

        llm = ChatOllama(model=get_model_name(), temperature=0, num_predict=2048, num_ctx=4096)

        fixes_by_id: dict[str, dict[str, Any]] = {}
        fixes_by_loc: dict[tuple[str, str], dict[str, Any]] = {}

        BATCH_SIZE = 5
        for batch_start in range(0, min(len(tool_bugs), 20), BATCH_SIZE):
            batch = tool_bugs[batch_start: batch_start + BATCH_SIZE]
            items = "\n\n".join(
                f"ID: {b['id']}\n"
                f"File: {b['file']}, Line {b['line_number']}\n"
                f"Issue: {b['title']}\n"
                f"Buggy code: {b['code_snippet']}"
                for b in batch
            )
            prompt = f"Fix these {len(batch)} code issues:\n\n{items}"

            try:
                response = llm.invoke([
                    SystemMessage(content=CODE_FIX_SYSTEM_PROMPT),
                    HumanMessage(content=prompt),
                ])
                parsed = _parse_llm_json(response.content)
                for fix in parsed.get("fixes", []):
                    fid = fix.get("id", "")
                    if fid:
                        fixes_by_id[fid] = fix
                    for b in batch:
                        loc_key = (b.get("file", ""), str(b.get("line_number", "")))
                        if loc_key not in fixes_by_loc and fix.get("fixed_code", ""):
                            fixes_by_loc[loc_key] = fix
                            break
            except Exception:
                pass

        tracer.log_tool_call(
            f"LLM ({get_model_name()})",
            f"Fixing {len(tool_bugs)} bug findings in batches of {BATCH_SIZE}",
            f"Got fixes for {len(fixes_by_id)} findings by ID",
        )

        final_bugs: list[dict[str, Any]] = []
        for bug in tool_bugs:
            merged = {**bug}
            loc_key = (bug.get("file", ""), str(bug.get("line_number", "")))
            llm_fix = fixes_by_id.get(bug.get("id", "")) or fixes_by_loc.get(loc_key, {})
            if llm_fix:
                fixed = llm_fix.get("fixed_code", "").strip()
                explanation = llm_fix.get("fix_explanation", "").strip()
                if fixed:
                    merged["fixed_code"] = fixed
                if explanation:
                    merged["fix_explanation"] = explanation
            if not merged.get("fixed_code"):
                fb_fixed, fb_explanation = generate_bug_fix(
                    merged.get("title", ""),
                    merged.get("code_snippet", ""),
                )
                merged["fixed_code"] = fb_fixed
                if not merged.get("fix_explanation"):
                    merged["fix_explanation"] = fb_explanation
            final_bugs.append(merged)

        final_opts: list[dict[str, Any]] = []

        trace = tracer.complete(
            f"Confirmed {len(final_bugs)} bugs | {len(final_opts)} optimizations"
        )

        return {
            "bugs": final_bugs,
            "optimizations": final_opts,
            "current_agent": "CodeQualityAgent",
            "status": "quality_scan_complete",
            "agent_traces": [trace],
        }

    except Exception as exc:
        trace = tracer.error(str(exc))
        return {
            "bugs": [],
            "optimizations": [],
            "status": "error",
            "current_agent": "CodeQualityAgent",
            "agent_traces": [trace],
        }
