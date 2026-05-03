"""
Agent 1: OrchestratorAgent  (Member 1)

Reads all project files recursively, detects languages and frameworks,
maps data flows and entry points, and decides the scan scope based on
the user's natural language prompt.

Outputs:
  - code_context: {files, languages, frameworks, entry_points, data_flows,
                   scan_scope, file_count, total_lines}
  - code_structure: backward-compat alias with same content
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import get_model_name
from src.observability import AgentTracer
from src.tools.code_reader import read_project_files

ORCHESTRATOR_SYSTEM_PROMPT: str = """You are OrchestratorAgent. Analyse the source code and output ONLY valid JSON (no markdown).

Output this exact schema:
{"languages":["Python"],"frameworks":["Flask"],"architectural_patterns":["REST API"],"entry_points":[{"type":"route","location":"GET /api/users","file":"app.py","method":"GET","parameters":["user_id"]}],"data_flows":[{"source":"request.args.get('q')","sink":"cursor.execute(query)","data_type":"user_input","is_user_input":true}],"security_observations":[]}

Only report what you can directly observe in the code."""


# ---------------------------------------------------------------------------
# Deterministic scan-scope classifier — does NOT rely on LLM output.
# This is the source of truth for LangGraph routing.
# ---------------------------------------------------------------------------
_SECURITY_KEYWORDS = {
    "security", "vulnerability", "vulnerabilities", "vulnerable",
    "inject", "injection", "xss", "csrf", "sql", "sqli",
    "exploit", "owasp", "secret", "password", "credential",
    "auth", "authentication", "authorization", "authorisation",
    "secure", "hack", "attack", "malicious", "sanitize", "sanitise",
    "encrypt", "encryption", "ssl", "tls", "token", "jwt",
    "cve", "cvss", "pentest", "penetration", "rce", "lfi", "rfi",
    "traversal", "overflow", "buffer", "leak", "exposure",
}

_QUALITY_KEYWORDS = {
    "bug", "bugs", "error", "errors", "crash", "debug", "fix", "fixes",
    "broken", "logic", "quality", "code quality",
    "optimize", "optimise", "optimization", "optimizations",
    "optimisation", "optimisations", "speed", "slow", "performance",
    "cache", "memory", "efficient", "efficiency", "refactor",
    "clean", "smell", "issue", "issues", "problem", "problems",
    "improve", "improvement", "maintenance", "maintainability",
}


def _determine_scan_scope(user_prompt: str) -> str:
    """Classify user intent deterministically using keyword matching.

    Returns:
        "security"  — only security/vulnerability scan needed
        "quality"   — only code-quality/bug/optimisation scan needed
        "full"      — both scans needed (or vague/general prompt)
    """
    words = set(user_prompt.lower().split())
    prompt_lower = user_prompt.lower()

    # Use both word-boundary match (for short keywords) and substring match
    has_security = any(kw in prompt_lower for kw in _SECURITY_KEYWORDS)
    has_quality  = any(kw in prompt_lower for kw in _QUALITY_KEYWORDS)

    if has_security and has_quality:
        return "full"       # user asked for both
    if has_security:
        return "security"   # vulnerability scan only
    if has_quality:
        return "quality"    # code-quality scan only
    return "full"           # vague / general → run everything


def _parse_llm_json(text: str) -> dict[str, Any]:
    """Parse JSON from LLM response, stripping markdown fences if present."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract the first JSON object
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    return {}


def run_orchestrator_agent(state: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the OrchestratorAgent.

    1. Reads all source files using the read_project_files tool.
    2. Sends a representative code summary to the LLM for analysis.
    3. Returns code_context populated with languages, frameworks, entry
       points, data flows, and scan scope.

    Args:
        state: Global state with project_path and user_prompt set.

    Returns:
        State update dict with code_context, code_structure, status.
    """
    tracer = AgentTracer("OrchestratorAgent")
    project_path: str = state.get("project_path", "")
    user_prompt: str = state.get("user_prompt", "")

    try:
        tracer.start(f"Scanning project: {project_path}")
        # ── Step 1: Read project files (Tool) ───────────────────────
        project_data: dict[str, Any] = read_project_files.invoke(
            {"project_path": project_path}
        )
        tracer.log_tool_call(
            "read_project_files",
            f"project_path={project_path}",
            f"Found {len(project_data.get('file_list', []))} files, "
            f"{project_data.get('total_lines', 0)} total lines",
        )

        if "error" in project_data:
            trace = tracer.error(project_data["error"])
            return {"agent_traces": [trace], "status": "error", "current_agent": "OrchestratorAgent"}

        file_contents: dict[str, str] = project_data.get("file_contents", {})
        if not file_contents:
            trace = tracer.error("No source code files found.")
            return {"agent_traces": [trace], "status": "error", "current_agent": "OrchestratorAgent"}

        # ── Step 2: Build code summary for LLM (keep within context window) ─
        # max_chars=2000 ≈ 500 tokens; system prompt ≈ 150 tokens; response 512
        # Total well within num_ctx=4096 for Mistral 7b
        code_summary_parts: list[str] = []
        total_chars = 0
        max_chars = 2000

        for fpath, content in file_contents.items():
            if total_chars + len(content) > max_chars:
                remaining = max_chars - total_chars
                if remaining > 200:
                    code_summary_parts.append(
                        f"\n--- FILE: {fpath} (truncated) ---\n{content[:remaining]}"
                    )
                break
            code_summary_parts.append(f"\n--- FILE: {fpath} ---\n{content}")
            total_chars += len(content)

        code_summary = "\n".join(code_summary_parts)

        # ── Step 3: LLM analysis (optional — pipeline continues on failure) ──
        analysis: dict[str, Any] = {}
        try:
            llm = ChatOllama(model=get_model_name(), temperature=0, num_predict=512, num_ctx=4096)
            messages = [
                SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT),
                HumanMessage(
                    content=(
                        f"User prompt: {user_prompt or 'Full security audit'}\n\n"
                        f"Analyse these source code files:\n\n{code_summary}"
                    )
                ),
            ]
            response = llm.invoke(messages)
            analysis = _parse_llm_json(response.content)
            tracer.log_tool_call(
                f"LLM ({get_model_name()})",
                f"Code analysis ({len(code_summary)} chars)",
                f"Response: {response.content[:200]}",
            )
        except Exception as llm_exc:
            # LLM is optional in orchestrator — log and continue with defaults
            tracer.log_tool_call(
                f"LLM ({get_model_name()})",
                f"Code analysis ({len(code_summary)} chars)",
                f"SKIPPED — LLM error: {llm_exc}",
            )

        # ── Step 4: Determine scan scope (deterministic — NOT from LLM) ──────
        scan_scope = _determine_scan_scope(user_prompt)
        tracer.log_tool_call(
            "scope_classifier",
            f"prompt='{user_prompt[:80]}'",
            f"scan_scope={scan_scope}",
        )

        # ── Step 5: Build code_context ────────────────────────────────
        # Detect languages from file extensions if LLM didn't provide them
        _ext_lang = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
                     ".java": "Java", ".rb": "Ruby", ".go": "Go", ".php": "PHP"}
        detected_langs = list({
            _ext_lang[ext]
            for f in file_contents
            for ext in [f[f.rfind("."):].lower()]
            if ext in _ext_lang
        })

        code_context: dict[str, Any] = {
            # From file reader
            "files": file_contents,
            "file_list": project_data.get("file_list", []),
            "file_count": len(file_contents),
            "total_lines": project_data.get("total_lines", 0),
            "language_distribution": project_data.get("language_distribution", {}),
            # From LLM (fall back to extension-based detection)
            "languages": analysis.get("languages", detected_langs or project_data.get("languages", [])),
            "frameworks": analysis.get("frameworks", []),
            "architectural_patterns": analysis.get("architectural_patterns", []),
            # Deterministic scope — keyword classifier overrides LLM
            "scan_scope": scan_scope,
            "entry_points": analysis.get("entry_points", []),
            "data_flows": analysis.get("data_flows", []),
            "security_observations": analysis.get("security_observations", []),
        }

        # Backward compat alias — note: file_contents intentionally excluded to keep
        # state lean; full contents are already in code_context["files"]
        code_structure: dict[str, Any] = {
            "languages": code_context["languages"],
            "frameworks": code_context["frameworks"],
            "file_list": code_context["file_list"],
            "file_count": code_context["file_count"],
            "total_lines": code_context["total_lines"],
        }

        trace = tracer.complete(
            f"Scanned {len(file_contents)} files | "
            f"Languages: {', '.join(code_context['languages'][:5])} | "
            f"Scope: {scan_scope}"
        )

        return {
            "code_context": code_context,
            "code_structure": code_structure,
            "scan_scope": scan_scope,      # top-level state key for LangGraph routing
            "status": "orchestrator_complete",
            "current_agent": "OrchestratorAgent",
            "agent_traces": [trace],
        }

    except Exception as exc:
        trace = tracer.error(str(exc))
        return {
            "status": "error",
            "current_agent": "OrchestratorAgent",
            "agent_traces": [trace],
        }
