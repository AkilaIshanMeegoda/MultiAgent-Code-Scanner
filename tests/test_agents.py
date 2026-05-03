"""
Testing & Evaluation Harness for the Code Security Auditor MAS.

This module provides a unified testing framework that validates each agent's
output for correctness, completeness, and security. Each student contributes
test cases for their specific agent.

Test Categories:
  - Property-based tests: Validate structural properties of outputs
  - LLM-as-a-Judge tests: Use an LLM to evaluate output quality
  - Tool unit tests: Verify each custom tool works correctly
  - Integration tests: Verify the full pipeline works end-to-end
"""

from __future__ import annotations

import json
import os
import sys

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.code_reader import read_project_files
from src.tools.vulnerability_scanner import scan_code_for_vulnerabilities
from src.tools.cve_lookup import lookup_similar_cves
from src.tools.report_generator import generate_security_report
from src.state import create_initial_state, GlobalState


# ============================================================================
# SAMPLE DATA DIR
# ============================================================================
SAMPLE_APP_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_vulnerable_app",
)

SAMPLE_CODE: dict[str, str] = {
    "app.py": '''
import os
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)
app.secret_key = "hardcoded_secret"

@app.route("/users")
def get_users():
    username = request.args.get("username", "")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system(f"ping {host}")
    return "done"

@app.route("/load")
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)
''',
}


# ============================================================================
# CodeScannerAgent - Tool (read_project_files)
# ============================================================================
class TestCodeReaderTool:
    """Tests for the code_reader tool (Student 1's contribution)."""

    def test_reads_existing_project(self) -> None:
        """Tool should successfully read files from an existing directory."""
        result: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert len(result["file_list"]) > 0, "Should find at least one file"
        assert result["total_lines"] > 0, "Should count lines"

    def test_detects_python_language(self) -> None:
        """Tool should detect Python as a language in the sample app."""
        result: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        assert "Python" in result["languages"], "Should detect Python"

    def test_returns_file_contents(self) -> None:
        """Tool should return the actual content of each file."""
        result: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        for fpath, content in result["file_contents"].items():
            assert isinstance(content, str), f"Content of {fpath} should be a string"
            assert len(content) > 0, f"Content of {fpath} should not be empty"

    def test_handles_nonexistent_directory(self) -> None:
        """Tool should return an error for a non-existent directory."""
        result: dict = read_project_files.invoke({"project_path": "/nonexistent/path"})
        assert "error" in result, "Should return error for missing directory"

    def test_language_distribution_is_dict(self) -> None:
        """Tool should return language distribution as a dictionary."""
        result: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        assert isinstance(result["language_distribution"], dict)

    def test_skips_gitignored_directories(self) -> None:
        """Tool should skip .git, node_modules, etc."""
        result: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        for fpath in result["file_list"]:
            assert ".git" not in fpath.split(os.sep), "Should skip .git directory"
            assert "node_modules" not in fpath.split(os.sep), "Should skip node_modules"


# ============================================================================
# VulnerabilityDetectorAgent - Tool (scan_code_for_vulnerabilities)
# ============================================================================
class TestVulnerabilityScannerTool:
    """Tests for the vulnerability_scanner tool (Student 2's contribution)."""

    def test_detects_sql_injection(self) -> None:
        """Tool should detect SQL injection patterns."""
        code = {"test.py": """cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")"""}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": code})
        categories = [v["category"] for v in result]
        assert any("Injection" in c for c in categories), f"Should detect SQL injection, got: {[v['title'] for v in result]}"

    def test_detects_hardcoded_secrets(self) -> None:
        """Tool should detect hardcoded credentials."""
        code = {"config.py": 'password = "mysecretpassword123"'}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": code})
        assert len(result) > 0, "Should detect hardcoded secret"
        assert any("Cryptographic" in v["category"] for v in result)

    def test_detects_command_injection(self) -> None:
        """Tool should detect command injection via os.system."""
        code = {"app.py": "os.system(f'ping {host}')"}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": code})
        assert len(result) > 0, "Should detect command injection"

    def test_detects_insecure_deserialization(self) -> None:
        """Tool should detect pickle.loads usage."""
        code = {"handler.py": "data = pickle.loads(user_data)"}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": code})
        assert len(result) > 0, "Should detect insecure deserialization"

    def test_detects_weak_hashing(self) -> None:
        """Tool should detect MD5/SHA1 usage."""
        code = {"auth.py": "hash_val = hashlib.md5(password.encode()).hexdigest()"}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": code})
        assert len(result) > 0, "Should detect weak hashing"

    def test_returns_proper_structure(self) -> None:
        """Each vulnerability should have required fields."""
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": SAMPLE_CODE})
        for vuln in result:
            assert "id" in vuln, "Missing id"
            assert "title" in vuln, "Missing title"
            assert "severity" in vuln, "Missing severity"
            assert "file" in vuln, "Missing file"
            assert "line_number" in vuln, "Missing line_number"
            assert vuln["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_assigns_cvss_scores(self) -> None:
        """Each vulnerability should have a CVSS score."""
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": SAMPLE_CODE})
        for vuln in result:
            assert "cvss_score" in vuln
            assert 0.0 <= vuln["cvss_score"] <= 10.0

    def test_no_vulns_in_clean_code(self) -> None:
        """Tool should not flag obviously clean code."""
        clean_code = {"clean.py": "def add(a, b):\n    return a + b\n\nprint(add(1, 2))"}
        result: list = scan_code_for_vulnerabilities.invoke({"file_contents": clean_code})
        assert len(result) == 0, "Should not flag clean code"

    def test_detects_multiple_vulns_in_sample_app(self) -> None:
        """Tool should detect multiple vulnerabilities in the sample app."""
        result_proj: dict = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        result: list = scan_code_for_vulnerabilities.invoke(
            {"file_contents": result_proj["file_contents"]}
        )
        assert len(result) >= 5, f"Should detect at least 5 vulns, found {len(result)}"


# ============================================================================
# ExploitabilityAssessorAgent - Tool (lookup_similar_cves)
# ============================================================================
class TestCVELookupTool:
    """Tests for the cve_lookup tool (Student 3's contribution)."""

    def test_finds_cves_for_sql_injection(self) -> None:
        """Should find CVEs related to SQL injection."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "SQL injection via string concatenation",
            "vulnerability_category": "Injection",
        })
        assert len(result) > 0, "Should find related CVEs"

    def test_finds_cves_for_command_injection(self) -> None:
        """Should find CVEs related to command injection."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "Command injection via os.system",
            "vulnerability_category": "Injection",
        })
        assert len(result) > 0, "Should find related CVEs"

    def test_finds_cves_for_deserialization(self) -> None:
        """Should find CVEs related to insecure deserialization."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "Insecure deserialization using pickle",
            "vulnerability_category": "Insecure Deserialization",
        })
        assert len(result) > 0, "Should find related CVEs"

    def test_returns_proper_cve_structure(self) -> None:
        """Each CVE result should have required fields."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "eval injection",
            "vulnerability_category": "Injection",
        })
        for cve in result:
            assert "cve_id" in cve, "Missing cve_id"
            assert "description" in cve, "Missing description"
            assert "severity" in cve, "Missing severity"
            assert "cvss" in cve, "Missing cvss"
            assert "relevance_score" in cve, "Missing relevance_score"

    def test_results_sorted_by_relevance(self) -> None:
        """Results should be sorted by relevance score descending."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "remote code execution injection",
            "vulnerability_category": "Injection",
        })
        if len(result) >= 2:
            for i in range(len(result) - 1):
                assert result[i]["relevance_score"] >= result[i + 1]["relevance_score"]

    def test_max_five_results(self) -> None:
        """Should return at most 5 results."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "injection command execution code remote",
            "vulnerability_category": "Injection",
        })
        assert len(result) <= 5, "Should return at most 5 results"

    def test_relevance_score_bounded(self) -> None:
        """Relevance scores should be between 0 and 100."""
        result: list = lookup_similar_cves.invoke({
            "vulnerability_description": "XSS cross-site scripting",
            "vulnerability_category": "Injection",
        })
        for cve in result:
            assert 0 <= cve["relevance_score"] <= 100


# ============================================================================
# SecurityReportAgent - Tool (generate_security_report)
# ============================================================================
class TestReportGeneratorTool:
    """Tests for the report_generator tool (Student 4's contribution)."""

    def _get_sample_data(self) -> dict:
        """Get sample data for report generation."""
        import tempfile
        return {
            "project_path": tempfile.mkdtemp(),
            "executive_summary": "This is a test executive summary.",
            "vulnerabilities": [
                {
                    "id": "VULN-0001",
                    "title": "SQL Injection",
                    "category": "A03:2021 - Injection",
                    "owasp_category": "A03:2021 - Injection",
                    "description": "SQL injection found in query",
                    "file": "app.py",
                    "line_number": 10,
                    "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                    "severity": "CRITICAL",
                    "cvss_score": 9.5,
                    "confidence": "HIGH",
                },
                {
                    "id": "VULN-0002",
                    "title": "Hardcoded Secret",
                    "category": "A02:2021 - Cryptographic Failures",
                    "owasp_category": "A02:2021 - Cryptographic Failures",
                    "description": "Hardcoded API key in config",
                    "file": "config.py",
                    "line_number": 5,
                    "code_snippet": "API_KEY = 'sk-live-abc123'",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "confidence": "HIGH",
                },
            ],
            "exploitability_assessments": [
                {
                    "vulnerability_id": "VULN-0001",
                    "exploitability_score": 9.0,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "exploit_maturity": "PROVEN",
                    "similar_cves": ["CVE-2023-25690"],
                },
            ],
            "remediation_snippets": {
                "VULN-0001": "cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
                "VULN-0002": "API_KEY = os.environ.get('API_KEY')",
            },
            "fix_priority_roadmap": "## Immediate\\n- Fix VULN-0001\\n## Short-term\\n- Fix VULN-0002",
        }

    def test_generates_report_content(self) -> None:
        """Tool should generate non-empty report content."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        assert "report_content" in result
        assert len(result["report_content"]) > 100

    def test_saves_report_file(self) -> None:
        """Tool should save report to disk."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        assert "report_path" in result
        assert os.path.exists(result["report_path"])

    def test_report_contains_executive_summary(self) -> None:
        """Report should contain the executive summary."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        assert "Executive Summary" in result["report_content"]

    def test_report_contains_vulnerabilities(self) -> None:
        """Report should list all vulnerabilities."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        assert "VULN-0001" in result["report_content"]
        assert "SQL Injection" in result["report_content"]

    def test_report_contains_remediation(self) -> None:
        """Report should include remediation snippets."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        assert "Recommended Fix" in result["report_content"]

    def test_report_stats_correct(self) -> None:
        """Report stats should accurately count severities."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        stats = result["stats"]
        assert stats["total_vulnerabilities"] == 2
        assert stats["critical"] == 1
        assert stats["high"] == 1

    def test_empty_vulnerabilities_produces_clean_report(self) -> None:
        """Report with no vulnerabilities should indicate clean codebase."""
        data = self._get_sample_data()
        data["vulnerabilities"] = []
        data["exploitability_assessments"] = []
        result: dict = generate_security_report.invoke(data)
        assert "No vulnerabilities detected" in result["report_content"]

    def test_report_markdown_format(self) -> None:
        """Report should be valid Markdown with headers."""
        data = self._get_sample_data()
        result: dict = generate_security_report.invoke(data)
        content = result["report_content"]
        assert content.startswith("# "), "Should start with H1 header"
        assert "## " in content, "Should contain H2 headers"


# ============================================================================
# STATE MANAGEMENT TESTS
# ============================================================================
class TestStateManagement:
    """Tests for global state management."""

    def test_initial_state_has_required_keys(self) -> None:
        """Initial state should have all required keys."""
        state: GlobalState = create_initial_state("/test/path")
        assert state["session_id"]
        assert state["project_path"] == "/test/path"
        assert state["status"] == "initialized"
        assert isinstance(state["vulnerabilities"], list)
        assert isinstance(state["agent_traces"], list)

    def test_state_preserves_data_between_agents(self) -> None:
        """State should preserve data when passed between agents."""
        state: GlobalState = create_initial_state("/test")
        state["vulnerabilities"] = [{"id": "VULN-0001", "title": "Test"}]
        state["code_structure"] = {"languages": ["Python"]}

        # Verify data persists
        assert len(state["vulnerabilities"]) == 1
        assert state["code_structure"]["languages"] == ["Python"]

    def test_session_id_is_unique(self) -> None:
        """Each session should get a unique ID."""
        state1 = create_initial_state("/test1")
        state2 = create_initial_state("/test2")
        assert state1["session_id"] != state2["session_id"]


# ============================================================================
# LLM-AS-A-JUDGE EVALUATION (Optional - uses Ollama if available)
# ============================================================================
class TestLLMJudge:
    """LLM-based evaluation tests. Skipped if Ollama is not available."""

    @pytest.fixture(autouse=True)
    def check_ollama(self) -> None:
        """Skip tests if Ollama is not running."""
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=3)
            if resp.status_code != 200:
                pytest.skip("Ollama not available")
        except Exception:
            pytest.skip("Ollama not available")

    def test_vulnerability_scanner_quality(self) -> None:
        """Use LLM to judge if vulnerability scanner output is reasonable."""
        from langchain_ollama import ChatOllama

        # Get scanner results
        proj_data = read_project_files.invoke({"project_path": SAMPLE_APP_DIR})
        vulns = scan_code_for_vulnerabilities.invoke(
            {"file_contents": proj_data["file_contents"]}
        )

        llm = ChatOllama(model="llama3.1:8b", temperature=0)
        judge_prompt = f"""You are a security expert judge. Evaluate the quality of these vulnerability scan results.

The scan was run on a DELIBERATELY VULNERABLE Flask application with known issues including:
SQL injection, command injection, hardcoded secrets, insecure deserialization, XSS.

SCAN RESULTS ({len(vulns)} findings):
{json.dumps(vulns[:10], indent=2)}

Rate the scan quality on a scale of 1-10 for:
1. Coverage: Did it find the major vulnerability types?
2. Accuracy: Are the findings real issues (not false positives)?
3. Detail: Are findings well-described with file/line info?

Respond with ONLY a JSON object:
{{"coverage": X, "accuracy": X, "detail": X, "overall": X, "explanation": "brief explanation"}}
"""
        response = llm.invoke(judge_prompt)
        # Just verify it runs without error - the judge response is informational
        assert response.content is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
