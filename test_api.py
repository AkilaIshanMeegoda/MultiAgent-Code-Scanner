"""Quick API test script - run with: python test_api.py"""
import json
import requests
import time
import subprocess
import sys

PORT = 8099

print("Starting test server...")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "server:app", "--port", str(PORT), "--no-access-log"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
time.sleep(4)

try:
    # Health check
    r = requests.get(f"http://localhost:{PORT}/api/health", timeout=5)
    print("Health:", r.json())

    # Start audit
    r2 = requests.post(
        f"http://localhost:{PORT}/api/audit",
        json={"project_path": "sample_vulnerable_app", "user_prompt": "test"},
        timeout=5,
    )
    print("Audit start:", r2.json())
    sid = r2.json()["session_id"]

    # Poll until done or 20s
    for i in range(10):
        time.sleep(2)
        r3 = requests.get(f"http://localhost:{PORT}/api/audit/{sid}", timeout=5)
        data = r3.json()
        status = data["status"]
        print(f"  [{i*2}s] status={status}")
        if status in ("complete", "error", "completed_with_errors"):
            print("Agent traces:")
            for t in data.get("agent_traces", []):
                print(f"  {t['agent_name']}: status={t['status']} | {t.get('output_summary','')[:80]}")
            break
    else:
        print("Timed out - still running")

finally:
    proc.terminate()
    out, err = proc.communicate(timeout=3)
    if err:
        print("\n--- Server stderr ---")
        print(err.decode()[-3000:])
