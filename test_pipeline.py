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
    for step in pipeline.stream(initial_state, stream_mode="updates"):
        step_count += 1
        for node_name, node_output in step.items():
            print(f"  Node '{node_name}' returned status={node_output.get('status', '?')}")
            traces = node_output.get("agent_traces", [])
            for t in traces:
                print(f"    Trace: {t.get('agent_name')} {t.get('status')} - {str(t.get('output_summary',''))[:100]}")
        if step_count > 10:
            print("Too many steps, stopping")
            break

    print(f"\nTotal steps: {step_count}")

except Exception as e:
    print(f"\nERROR: {e}")
    traceback.print_exc()

