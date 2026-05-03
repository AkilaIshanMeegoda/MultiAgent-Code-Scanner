"""Debug test - run pipeline directly and catch all errors"""
import traceback
import sys
import os

os.chdir(r"D:\Projects\Code-Security-Checker")

try:
    from src.pipeline import build_pipeline
    from src.state import create_initial_state
    from src.observability import console

    print("Imports OK")

    project_path = os.path.abspath("sample_vulnerable_app")
    user_prompt = "test"

    print(f"Project path: {project_path}")

    initial_state = dict(create_initial_state(project_path, user_prompt))
    initial_state["agent_traces"] = []

    print(f"Initial state keys: {list(initial_state.keys())}")

    pipeline = build_pipeline()
    print("Pipeline built OK")

    print("Starting stream...")
    step_count = 0
    

except Exception as e:
    print(f"\nERROR: {e}")
    traceback.print_exc()

