"""
Agent 1: CodeScannerAgent

Reads source code files from a local project, identifies programming languages,
frameworks, architectural patterns, and maps data flow through the application.

This agent is the first in the pipeline. It produces the foundational analysis
that all downstream agents depend on.

Author: Student 1
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import get_model_name
from src.observability import AgentTracer
from src.tools.code_reader import read_project_files

# System prompt with strict constraints to minimize hallucination
CODE_SCANNER_SYSTEM_PROMPT: str = """You are CodeScannerAgent, a specialized code analysis expert.
Your ONLY job is to analyze source code structure and produce a structured JSON report.

STRICT RULES:
1. ONLY report what you can directly observe in the provided source code.
2. NEVER guess, assume, or hallucinate information not present in the code.
3. If you cannot determine something, say "unknown" - do NOT make it up.
4. Your output must be valid JSON and nothing else.

You will receive the contents of source code files. You must analyze them and return a JSON object with these exact keys:

{
  "frameworks": ["list of frameworks detected from imports/dependencies"],
  "architectural_patterns": ["list of patterns like MVC, REST API, microservice, etc."],
  "entry_points": [
    {
      "type": "route/endpoint/function/main",
      "location": "description of the entry point",
      "file": "filename",
      "method": "HTTP method or function name",
      "parameters": ["list of parameters"]
    }
  ],
  "data_flows": [
    {
      "source": "where data enters (e.g., user input, request body)",
      "sink": "where data goes (e.g., database, response, file)",
      "path": ["list of functions/methods data passes through"],
      "data_type": "type of data",
      "is_user_input": true/false
    }
  ],
  "security_relevant_observations": ["list of security-relevant observations"]
}

ONLY output the JSON object. No explanations, no markdown, no extra text."""


def run_code_scanner_agent(state: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the CodeScannerAgent to analyze project source code.

    Reads all source files from the project directory, sends them to the LLM
    for structural analysis, and updates the global state with findings.

    Args:
        state: The current global state with project_path set.

    Returns:
        State update dict with code_structure, data_flows, framework_info,
        and entry_points populated.
    """
    tracer = AgentTracer("CodeScannerAgent")
    project_path: str = state.get("project_path", "")
    tracer.start(f"Scanning project at: {project_path}")

    try:
        # Step 1: Use the code reader tool to get file contents
        project_data: dict[str, Any] = read_project_files.invoke(
            {"project_path": project_path}
        )
        tracer.log_tool_call(
            "read_project_files",
            f"project_path={project_path}",
            f"Found {len(project_data.get('file_list', []))} files, "
            f"{project_data.get('total_lines', 0)} lines",
        )

        if "error" in project_data:
            trace = tracer.error(project_data["error"])
            return {"agent_traces": [trace], "status": "error"}

        file_contents: dict[str, str] = project_data.get("file_contents", {})
        if not file_contents:
            trace = tracer.error("No source code files found in the project.")
            return {"agent_traces": [trace], "status": "error"}

        # Step 2: Prepare code summary for LLM (truncate if too large)
        code_summary_parts: list[str] = []
        total_chars: int = 0
        max_chars: int = 4000  # Keep within context window

        for fpath, content in file_contents.items():
            if total_chars + len(content) > max_chars:
                remaining = max_chars - total_chars
                if remaining > 200:
                    code_summary_parts.append(f"\n--- FILE: {fpath} (truncated) ---\n{content[:remaining]}")
                break
            code_summary_parts.append(f"\n--- FILE: {fpath} ---\n{content}")
            total_chars += len(content)

        code_summary: str = "\n".join(code_summary_parts)

        # Step 3: Call LLM for analysis
        llm = ChatOllama(model=get_model_name(), temperature=0, num_predict=2048, num_ctx=2048)

        messages = [
            SystemMessage(content=CODE_SCANNER_SYSTEM_PROMPT),
            HumanMessage(content=f"Analyze the following source code files:\n\n{code_summary}"),
        ]

        response = llm.invoke(messages)
        response_text: str = response.content

        tracer.log_tool_call(
            "LLM (llama3.1:8b)",
            f"Code analysis request ({len(code_summary)} chars)",
            f"Response: {response_text[:200]}",
        )

        # Step 4: Parse LLM response
        analysis: dict[str, Any] = _parse_llm_json(response_text)

        # Step 5: Build state update
        code_structure = {
            "languages": project_data.get("languages", []),
            "frameworks": analysis.get("frameworks", []),
            "architectural_patterns": analysis.get("architectural_patterns", []),
            "file_list": project_data.get("file_list", []),
            "total_lines": project_data.get("total_lines", 0),
            "file_contents": file_contents,
        }
        data_flows = analysis.get("data_flows", [])
        entry_points = analysis.get("entry_points", [])

        trace = tracer.complete(
            f"Found {len(entry_points)} entry points, "
            f"{len(data_flows)} data flows, "
            f"Languages: {code_structure.get('languages', [])}"
        )

        return {
            "code_structure": code_structure,
            "data_flows": data_flows,
            "framework_info": {
                "detected_frameworks": analysis.get("frameworks", []),
                "language_distribution": project_data.get("language_distribution", {}),
            },
            "entry_points": entry_points,
            "current_agent": "CodeScannerAgent",
            "status": "code_scanning_complete",
            "agent_traces": [trace],
        }

    except Exception as e:
        trace = tracer.error(str(e))
        return {"agent_traces": [trace], "status": "error"}


def _parse_llm_json(text: str) -> dict[str, Any]:
    """Parse JSON from LLM response, handling common formatting issues.

    Args:
        text: The raw LLM response text.

    Returns:
        Parsed dictionary from the JSON, or empty dict on failure.
    """
    # Try direct parse first
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from markdown code block
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start) if "```" in text[start:] else len(text)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass

    if "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start) if "```" in text[start:] else len(text)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass

    # Try to find JSON object in the text
    brace_start = text.find("{")
    brace_end = text.rfind("}") + 1
    if brace_start >= 0 and brace_end > brace_start:
        try:
            return json.loads(text[brace_start:brace_end])
        except json.JSONDecodeError:
            pass

    return {}
