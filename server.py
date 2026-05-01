"""
FastAPI Backend Server for the Code Security Auditor MAS.

Provides REST API endpoints for the React frontend to trigger audits,
stream agent progress via SSE, and retrieve results.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel


app = FastAPI(
    title="Code Security Auditor API",
    version="1.0.0",
    description="Multi-Agent System for automated code security auditing",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory store for audit sessions ──────────────────────────────────────

_sessions: dict[str, dict[str, Any]] = {}
_session_events: dict[str, list[dict[str, Any]]] = {}


# ── Request / Response Models ───────────────────────────────────────────────

class AuditRequest(BaseModel):
    project_path: str


class ConfigUpdateRequest(BaseModel):
    ollama_model: str


# ── Helper: push an SSE event ──────────────────────────────────────────────

def _push_event(session_id: str, event_type: str, data: dict[str, Any]) -> None:
    if session_id not in _session_events:
        _session_events[session_id] = []
    _session_events[session_id].append({
        "type": event_type,
        "data": data,
        "timestamp": datetime.now().isoformat(),
    })


# ── Background audit runner ────────────────────────────────────────────────

def _run_audit_background(session_id: str, project_path: str) -> None:
    """Run the full audit pipeline in a background thread, pushing SSE events."""
    try:
        from src.pipeline import build_pipeline
        from src.state import create_initial_state
        from src.observability import console

        _push_event(session_id, "pipeline_start", {"project_path": project_path})

        initial_state = dict(create_initial_state(project_path))
        initial_state["agent_traces"] = []
        _sessions[session_id]["state"] = initial_state

        # Node name → display agent name mapping
        _agent_names = {
            "code_scanner": "CodeScannerAgent",
            "vulnerability_detector": "VulnerabilityDetectorAgent",
            "exploitability_assessor": "ExploitabilityAssessorAgent",
            "security_report": "SecurityReportAgent",
            "handle_error": "ErrorHandler",
        }

        # Build and print graph topology
        pipeline = build_pipeline()
        console.print("\n[bold blue]📊 LangGraph Graph Topology:[/bold blue]")
        try:
            graph = pipeline.get_graph()
            node_names = [n for n in graph.nodes if n not in ("__start__", "__end__")]
            console.print(f"[dim]  Nodes : {', '.join(node_names)}[/dim]")
            for edge in graph.edges:
                src = "START" if edge.source == "__start__" else edge.source
                tgt = "END" if edge.target == "__end__" else edge.target
                console.print(f"[dim]  Edge  : {src} → {tgt}[/dim]")
        except Exception:
            pass

        console.print("\n[bold blue]📡 LangGraph Streaming Execution:[/bold blue]\n")

        # Track which nodes have started (stream gives us completions only)
        final_state = dict(initial_state)
        node_order: list[str] = []
        prev_node: str | None = None

        for step in pipeline.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in step.items():
                agent_label = _agent_names.get(node_name, node_name)

                # Emit agent_start for prev node if not yet done
                if prev_node != node_name:
                    _push_event(session_id, "agent_start", {"agent": agent_label})
                    prev_node = node_name

                node_order.append(node_name)
                is_error = isinstance(node_output, dict) and node_output.get("status") == "error"
                icon = "❌" if is_error else "✅"
                console.print(
                    f"[bold blue]  [LangGraph][/bold blue] {icon} "
                    f"Node [cyan]{node_name!r}[/cyan] completed"
                )

                # Merge node output into final_state
                if isinstance(node_output, dict):
                    for key, val in node_output.items():
                        if key == "agent_traces":
                            final_state.setdefault("agent_traces", [])
                            if isinstance(val, list):
                                final_state["agent_traces"].extend(val)
                        else:
                            final_state[key] = val

                traces = final_state.get("agent_traces", [])
                _push_event(session_id, "agent_complete", {
                    "agent": agent_label,
                    "trace": traces[-1] if traces else {},
                })

                if is_error:
                    _sessions[session_id]["status"] = "error"
                    _sessions[session_id]["state"] = final_state
                    _push_event(session_id, "pipeline_error", {"error": f"{agent_label} failed"})
                    return

        if node_order:
            console.print(
                f"\n[bold blue]  [LangGraph][/bold blue] "
                f"Execution path: {' → '.join(node_order)}\n"
            )

        _sessions[session_id]["status"] = "complete"
        _sessions[session_id]["state"] = final_state
        _push_event(session_id, "pipeline_complete", {
            "vulnerabilities_count": len(final_state.get("vulnerabilities", [])),
            "severity_summary": final_state.get("severity_summary", {}),
        })

    except Exception as exc:
        _sessions[session_id]["status"] = "error"
        _push_event(session_id, "pipeline_error", {"error": str(exc)})


# ── API Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    """Check if the backend and Ollama are reachable."""
    ollama_ok = False
    model_name = "unknown"
    try:
        import json as _json
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        with open(config_path, "r") as f:
            cfg = _json.load(f)
        model_name = cfg.get("ollama_model", "unknown")

        import urllib.request
        req = urllib.request.Request(
            cfg.get("ollama_base_url", "http://localhost:11434") + "/api/tags"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            ollama_ok = resp.status == 200
    except Exception:
        pass

    return {
        "status": "ok",
        "ollama_connected": ollama_ok,
        "model": model_name,
    }


@app.post("/api/audit")
def start_audit(req: AuditRequest):
    """Start a new security audit in the background."""
    project_path = os.path.abspath(req.project_path)
    if not os.path.isdir(project_path):
        raise HTTPException(status_code=400, detail=f"Directory not found: {project_path}")

    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "id": session_id,
        "project_path": project_path,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "state": {},
    }
    _session_events[session_id] = []

    thread = threading.Thread(target=_run_audit_background, args=(session_id, project_path), daemon=True)
    thread.start()

    return {"session_id": session_id, "status": "running"}


@app.get("/api/audit/{session_id}/events")
def stream_events(session_id: str):
    """SSE endpoint — streams agent progress events."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    def event_generator():
        last_idx = 0
        while True:
            events = _session_events.get(session_id, [])
            while last_idx < len(events):
                evt = events[last_idx]
                yield f"data: {json.dumps(evt)}\n\n"
                last_idx += 1
                if evt["type"] in ("pipeline_complete", "pipeline_error"):
                    return
            time.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/audit/{session_id}")
def get_audit_result(session_id: str):
    """Get the full audit result for a completed session."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    state = session.get("state", {})

    # Serialise agent_traces (remove non-serialisable bits)
    traces = []
    for t in state.get("agent_traces", []):
        traces.append({
            "agent_name": t.get("agent_name", ""),
            "status": t.get("status", ""),
            "duration_seconds": t.get("duration_seconds", 0),
            "tool_calls_count": t.get("tool_calls_count", 0),
            "output_summary": t.get("output_summary", ""),
        })

    return {
        "session_id": session_id,
        "status": session["status"],
        "project_path": session["project_path"],
        "started_at": session.get("started_at", ""),
        "completed_at": state.get("completed_at", ""),
        "severity_summary": state.get("severity_summary", {}),
        "vulnerabilities": state.get("vulnerabilities", []),
        "exploitability_assessments": state.get("exploitability_assessments", []),
        "priority_order": state.get("priority_order", []),
        "risk_matrix": state.get("risk_matrix", {}),
        "executive_summary": state.get("executive_summary", ""),
        "full_report": state.get("full_report", ""),
        "agent_traces": traces,
        "code_structure": {
            "languages": state.get("code_structure", {}).get("languages", []),
            "frameworks": state.get("code_structure", {}).get("frameworks", []),
            "total_lines": state.get("code_structure", {}).get("total_lines", 0),
            "file_count": len(state.get("code_structure", {}).get("file_list", [])),
        },
    }


@app.get("/api/config")
def get_config():
    """Return current config.json values."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


@app.put("/api/config")
def update_config(req: ConfigUpdateRequest):
    """Update the Ollama model in config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, "r") as f:
            cfg = json.load(f)
        cfg["ollama_model"] = req.ollama_model
        with open(config_path, "w") as f:
            json.dump(cfg, f, indent=4)
        return {"status": "ok", "ollama_model": req.ollama_model}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions")
def list_sessions():
    """List all audit sessions."""
    results = []
    for sid, session in _sessions.items():
        state = session.get("state", {})
        results.append({
            "session_id": sid,
            "project_path": session["project_path"],
            "status": session["status"],
            "started_at": session.get("started_at", ""),
            "vulnerability_count": len(state.get("vulnerabilities", [])),
            "severity_summary": state.get("severity_summary", {}),
        })
    return results
