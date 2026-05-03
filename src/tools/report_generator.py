"""
Tool 4: Security Report Generator

This tool generates structured security audit reports in Markdown format,
including executive summaries, technical findings, remediation code snippets,
and priority roadmaps. Used by the SecurityReportAgent.

Author: Student 4 (SecurityReportAgent owner)
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from langchain_core.tools import tool


def _severity_badge(severity: str) -> str:
    """Generate a markdown severity badge.

    Args:
        severity: The severity level string.

    Returns:
        A formatted severity indicator string.
    """
    badges: dict[str, str] = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
    }
    return badges.get(severity.upper(), severity)


@tool
def generate_security_report(
    project_path: str,
    executive_summary: str,
    vulnerabilities: list[dict[str, Any]],
    exploitability_assessments: list[dict[str, Any]],
    remediation_snippets: dict[str, str],
    fix_priority_roadmap: str,
    bugs: list[dict[str, Any]] | None = None,
    optimizations: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Generate a comprehensive penetration-testing-style security audit report in Markdown.

    This tool creates a structured security report that includes an executive summary,
    detailed technical findings with severity levels, remediation code snippets, a
    prioritized fix roadmap, bug findings, and optimization suggestions.
    The report is saved to disk and returned as a string.

    Args:
        project_path: Absolute path to the project that was scanned.
        executive_summary: High-level summary of the security posture.
        vulnerabilities: List of vulnerability dictionaries with details.
        exploitability_assessments: List of exploitability assessment dictionaries.
        remediation_snippets: Dictionary mapping vulnerability IDs to fix code snippets.
        fix_priority_roadmap: Text describing the recommended fix order.
        bugs: Optional list of bug dictionaries from BugDetectorAgent.
        optimizations: Optional list of optimization dictionaries from OptimizationAdvisorAgent.

    Returns:
        A dictionary containing:
            - report_content: The full Markdown report as a string
            - report_path: Path where the report was saved
            - stats: Summary statistics about the findings
    """
    if bugs is None:
        bugs = []
    if optimizations is None:
        optimizations = []
    timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    project_name: str = os.path.basename(project_path)

    # Count severity levels
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in vulnerabilities:
        sev: str = vuln.get("severity", "MEDIUM").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total_vulns: int = len(vulnerabilities)

    # Build exploitability lookup
    exploit_lookup: dict[str, dict[str, Any]] = {}
    for assessment in exploitability_assessments:
        vid: str = assessment.get("vulnerability_id", "")
        exploit_lookup[vid] = assessment

    # ---- Build Report ----
    report_lines: list[str] = []

    report_lines.append(f"# 🔒 Security Audit Report: {project_name}")
    report_lines.append(f"\n**Generated:** {timestamp}")
    report_lines.append(f"**Project Path:** `{project_path}`")
    report_lines.append(f"**Total Vulnerabilities Found:** {total_vulns}")
    report_lines.append(f"**Total Bugs Found:** {len(bugs)}")
    report_lines.append(f"**Total Optimization Suggestions:** {len(optimizations)}")
    report_lines.append("")

    # Severity Summary Table
    report_lines.append("## Severity Summary")
    report_lines.append("")
    report_lines.append("| Severity | Count |")
    report_lines.append("|----------|-------|")
    for sev, count in severity_counts.items():
        report_lines.append(f"| {_severity_badge(sev)} | {count} |")
    report_lines.append("")

    # Executive Summary
    report_lines.append("---")
    report_lines.append("## Executive Summary")
    report_lines.append("")
    report_lines.append(executive_summary if executive_summary else "_No executive summary provided._")
    report_lines.append("")

    # Technical Findings
    report_lines.append("---")
    report_lines.append("## Technical Findings")
    report_lines.append("")

    if not vulnerabilities:
        report_lines.append("✅ No vulnerabilities detected. The codebase appears secure.")
    else:
        # Sort by severity (CRITICAL first)
        severity_order: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns: list[dict[str, Any]] = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "MEDIUM").upper(), 4),
        )

        for i, vuln in enumerate(sorted_vulns, start=1):
            vid: str = vuln.get("id", f"VULN-{i:04d}")
            report_lines.append(f"### {i}. [{vid}] {vuln.get('title', 'Unknown Vulnerability')}")
            report_lines.append("")
            report_lines.append(f"- **Severity:** {_severity_badge(vuln.get('severity', 'MEDIUM'))}")
            report_lines.append(f"- **CVSS Score:** {vuln.get('cvss_score', 'N/A')}")
            report_lines.append(f"- **OWASP Category:** {vuln.get('owasp_category', 'N/A')}")
            report_lines.append(f"- **File:** `{vuln.get('file', 'Unknown')}`")
            report_lines.append(f"- **Line:** {vuln.get('line_number', 'N/A')}")
            report_lines.append(f"- **Confidence:** {vuln.get('confidence', 'MEDIUM')}")
            report_lines.append("")
            report_lines.append(f"**Description:** {vuln.get('description', 'No description')}")
            report_lines.append("")

            snippet: str = vuln.get("code_snippet", "")
            current: str = vuln.get("current_code", snippet)
            fixed: str = vuln.get("fixed_code", "")
            explanation: str = vuln.get("fix_explanation", "")

            if current:
                report_lines.append(f"**Vulnerable Code** (`{vuln.get('file', '')}` line {vuln.get('line_number', 'N/A')}):")
                report_lines.append("```")
                report_lines.append(current)
                report_lines.append("```")
                report_lines.append("")

            if fixed:
                report_lines.append("**Fixed Code:**")
                report_lines.append("```")
                report_lines.append(fixed)
                report_lines.append("```")
                if explanation:
                    report_lines.append(f"*{explanation}*")
                report_lines.append("")
            elif explanation:
                report_lines.append(f"**Remediation:** {explanation}")
                report_lines.append("")

            report_lines.append("---")
            report_lines.append("")

    # Fix Priority Roadmap
    report_lines.append("## Fix Priority Roadmap")
    report_lines.append("")
    report_lines.append(fix_priority_roadmap if fix_priority_roadmap else "_No roadmap provided._")
    report_lines.append("")

    # Bugs Section
    if bugs:
        report_lines.append("---")
        report_lines.append("## Bug Findings")
        report_lines.append("")
        report_lines.append(f"**Total bugs detected:** {len(bugs)}")
        report_lines.append("")
        for i, bug in enumerate(bugs, start=1):
            bid = bug.get("id", f"BUG-{i:04d}")
            report_lines.append(f"### {i}. [{bid}] {bug.get('title', 'Unknown Bug')}")
            report_lines.append("")
            report_lines.append(f"- **Severity:** {_severity_badge(bug.get('severity', 'LOW'))}")
            report_lines.append(f"- **Category:** {bug.get('category', 'N/A')}")
            report_lines.append(f"- **File:** `{bug.get('file', 'Unknown')}`")
            report_lines.append(f"- **Line:** {bug.get('line_number', 'N/A')}")
            report_lines.append("")
            report_lines.append(f"**Description:** {bug.get('description', 'No description')}")
            report_lines.append("")
            current_b: str = bug.get("current_code", bug.get("code_snippet", ""))
            fixed_b: str = bug.get("fixed_code", "")
            explanation_b: str = bug.get("fix_explanation", "")
            if current_b:
                report_lines.append(f"**Buggy Code** (`{bug.get('file', '')}` line {bug.get('line_number', 'N/A')}):")
                report_lines.append("```")
                report_lines.append(current_b)
                report_lines.append("```")
                report_lines.append("")
            if fixed_b:
                report_lines.append("**Fixed Code:**")
                report_lines.append("```")
                report_lines.append(fixed_b)
                report_lines.append("```")
                if explanation_b:
                    report_lines.append(f"*{explanation_b}*")
                report_lines.append("")
            elif explanation_b:
                report_lines.append(f"**Fix:** {explanation_b}")
                report_lines.append("")
        report_lines.append("")

    # Optimizations Section
    if optimizations:
        report_lines.append("---")
        report_lines.append("## Optimization Suggestions")
        report_lines.append("")
        report_lines.append(f"**Total suggestions:** {len(optimizations)}")
        report_lines.append("")
        for i, opt in enumerate(optimizations, start=1):
            oid = opt.get("id", f"OPT-{i:04d}")
            report_lines.append(f"### {i}. [{oid}] {opt.get('title', 'Optimization')}")
            report_lines.append("")
            report_lines.append(f"- **Impact:** {opt.get('impact', 'N/A')}")
            report_lines.append(f"- **Category:** {opt.get('category', 'N/A')}")
            report_lines.append(f"- **File:** `{opt.get('file', 'N/A')}`")
            report_lines.append("")
            report_lines.append(f"**Description:** {opt.get('description', 'No description')}")
            report_lines.append("")
            current_o: str = opt.get("current_code", opt.get("code_snippet", ""))
            fixed_o: str = opt.get("fixed_code", "")
            explanation_o: str = opt.get("fix_explanation", "")
            if current_o:
                report_lines.append(f"**Current Code** (`{opt.get('file', '')}` line {opt.get('line_number', 'N/A')}):")
                report_lines.append("```")
                report_lines.append(current_o)
                report_lines.append("```")
                report_lines.append("")
            if fixed_o:
                report_lines.append("**Optimized Code:**")
                report_lines.append("```")
                report_lines.append(fixed_o)
                report_lines.append("```")
                if explanation_o:
                    report_lines.append(f"*{explanation_o}*")
                report_lines.append("")
            elif explanation_o:
                report_lines.append(f"**Suggestion:** {explanation_o}")
                report_lines.append("")
        report_lines.append("")

    # Footer
    report_lines.append("---")
    report_lines.append("*Report generated by Code Security Auditor MAS*")
    report_lines.append(f"*Timestamp: {timestamp}*")

    report_content: str = "\n".join(report_lines)

    # Save report to file
    reports_dir: str = os.path.join(project_path, "security_reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_filename: str = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path: str = os.path.join(reports_dir, report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return {
        "report_content": report_content,
        "report_path": report_path,
        "stats": {
            "total_vulnerabilities": total_vulns,
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
        },
    }
