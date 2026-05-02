"""Configuration loader for the Code Security Auditor."""

from __future__ import annotations

import json
import os

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")

def get_model_name() -> str:
    """Return the configured Ollama model name."""
    try:
        with open(_CONFIG_PATH, "r") as f:
            return json.load(f).get("ollama_model", "llama3.2:3b")
    except (OSError, json.JSONDecodeError):
        return "llama3.2:3b"
