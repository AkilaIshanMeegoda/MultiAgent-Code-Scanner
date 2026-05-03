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

    

except Exception as e:
    print(f"\nERROR: {e}")
    traceback.print_exc()

