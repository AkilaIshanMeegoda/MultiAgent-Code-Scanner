"""
Code Security Auditor - Main Entry Point

Run a security audit on any local project directory using the multi-agent system.

Usage:
    python main.py <project_path>
    python main.py                     # Uses the sample vulnerable project

Example:
    python main.py ./sample_vulnerable_app
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Main entry point for the Code Security Auditor."""
    # Determine project path
    if len(sys.argv) > 1:
        project_path: str = os.path.abspath(sys.argv[1])
    else:
        # Default to sample project
        project_path = os.path.join(os.path.dirname(__file__), "sample_vulnerable_app")

    if not os.path.isdir(project_path):
        print(f"Error: Directory not found: {project_path}")
        print(f"Usage: python main.py <project_path>")
        sys.exit(1)

    # Import here to allow clean error messages for missing deps
    try:
        from src.pipeline import run_security_audit
    except ImportError as e:
        print(f"Error: Missing dependency - {e}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)

    # Run the audit
    final_state = run_security_audit(project_path)

    # Check for report
    report = final_state.get("full_report", "")
    if report:
        print(f"\n{'='*70}")
        print("REPORT PREVIEW (first 500 chars):")
        print("="*70)
        print(report[:500])
        print(f"\n... Full report saved to project's security_reports/ directory")
    else:
        print("\nNo report generated. Check logs for errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
