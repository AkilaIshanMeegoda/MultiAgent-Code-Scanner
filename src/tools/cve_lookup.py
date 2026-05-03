"""
Tool 3: Local CVE Database Lookup

This tool maintains and queries a local CVE (Common Vulnerabilities and Exposures)
database stored as a JSON file. It allows the ExploitabilityAssessorAgent to find
similar known exploits for detected vulnerabilities without requiring internet access.

Author: Student 3 (ExploitabilityAssessorAgent owner)
"""

from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.tools import tool

# Path to the local CVE database file
CVE_DB_PATH: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "cve_database.json")

# Built-in CVE entries for common vulnerability types
DEFAULT_CVE_DATABASE: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "exploit_complexity": "LOW",
        "keywords": ["log4j", "jndi", "remote code execution", "deserialization"],
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Apache HTTP Server Path Traversal & RCE",
        "category": "Broken Access Control",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["path traversal", "directory traversal", "file access"],
    },
    {
        "cve_id": "CVE-2019-16759",
        "description": "vBulletin Remote Code Execution via eval injection",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["eval", "exec", "code execution", "command injection"],
    },
    {
        "cve_id": "CVE-2017-5638",
        "description": "Apache Struts2 Remote Code Execution",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "exploit_complexity": "LOW",
        "keywords": ["command injection", "os.system", "subprocess", "remote code execution"],
    },
    {
        "cve_id": "CVE-2020-1938",
        "description": "Apache Tomcat AJP File Read/Inclusion (Ghostcat)",
        "category": "Broken Access Control",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "keywords": ["file inclusion", "path traversal", "file read"],
    },
    {
        "cve_id": "CVE-2021-3129",
        "description": "Laravel Debug Mode Remote Code Execution",
        "category": "Security Misconfiguration",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["debug mode", "DEBUG=True", "error disclosure"],
    },
    {
        "cve_id": "CVE-2019-11358",
        "description": "jQuery Prototype Pollution via Object.extend",
        "category": "Injection",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "exploit_complexity": "MEDIUM",
        "keywords": ["prototype pollution", "xss", "cross-site scripting", "innerHTML"],
    },
    {
        "cve_id": "CVE-2022-22965",
        "description": "Spring Framework RCE (Spring4Shell)",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["spring", "java", "remote code execution", "class loader"],
    },
    {
        "cve_id": "CVE-2021-23369",
        "description": "Handlebars Template Injection leading to RCE",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["template injection", "ssti", "server-side template"],
    },
    {
        "cve_id": "CVE-2020-36518",
        "description": "Jackson Databind Deserialization of Untrusted Data",
        "category": "Insecure Deserialization",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "MEDIUM",
        "keywords": ["deserialization", "pickle", "yaml", "marshal", "unserialize"],
    },
    {
        "cve_id": "CVE-2018-1000006",
        "description": "Electron Protocol Handler Command Injection",
        "category": "Injection",
        "severity": "HIGH",
        "cvss": 8.8,
        "exploit_complexity": "LOW",
        "keywords": ["command injection", "os.system", "shell", "subprocess"],
    },
    {
        "cve_id": "CVE-2021-29200",
        "description": "Apache OFBiz SSRF via XML External Entities",
        "category": "SSRF",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "keywords": ["ssrf", "request forgery", "user-controlled url", "xxe"],
    },
    {
        "cve_id": "CVE-2018-0114",
        "description": "Cisco node-jose JWT Signature Bypass (alg:none)",
        "category": "Authentication Failures",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["jwt", "none algorithm", "token bypass", "authentication"],
    },
    {
        "cve_id": "CVE-2022-0778",
        "description": "OpenSSL Infinite Loop in BN_mod_sqrt()",
        "category": "Cryptographic Failures",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "keywords": ["ssl", "tls", "certificate", "verify", "crypto"],
    },
    {
        "cve_id": "CVE-2019-5418",
        "description": "Rails File Content Disclosure via Accept header",
        "category": "Broken Access Control",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "keywords": ["file disclosure", "path traversal", "sensitive data"],
    },
    {
        "cve_id": "CVE-2023-25690",
        "description": "Apache HTTP Server HTTP Request Smuggling",
        "category": "Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["sql injection", "http smuggling", "request injection"],
    },
    {
        "cve_id": "CVE-2021-27568",
        "description": "Netmask npm package SSRF via octal input",
        "category": "SSRF",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "exploit_complexity": "LOW",
        "keywords": ["ssrf", "ip bypass", "input validation"],
    },
    {
        "cve_id": "CVE-2020-7660",
        "description": "serialize-javascript XSS via crafted input",
        "category": "Injection",
        "severity": "HIGH",
        "cvss": 8.1,
        "exploit_complexity": "MEDIUM",
        "keywords": ["xss", "cross-site scripting", "innerHTML", "document.write"],
    },
    {
        "cve_id": "CVE-2020-28243",
        "description": "SaltStack Salt Command Injection via minion ID",
        "category": "Injection",
        "severity": "HIGH",
        "cvss": 7.8,
        "exploit_complexity": "LOW",
        "keywords": ["command injection", "os.system", "shell execution"],
    },
    {
        "cve_id": "CVE-2022-29464",
        "description": "WSO2 Unrestricted File Upload to RCE",
        "category": "Broken Access Control",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "keywords": ["file upload", "unrestricted upload", "remote code execution"],
    },
]


def _load_cve_database() -> list[dict[str, Any]]:
    """Load the CVE database from disk, falling back to defaults.

    Returns:
        List of CVE entry dictionaries.
    """
    if os.path.exists(CVE_DB_PATH):
        try:
            with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
                data: list[dict[str, Any]] = json.load(f)
                if data:  # Only use file data if non-empty
                    return data
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_CVE_DATABASE


def _save_cve_database(database: list[dict[str, Any]]) -> None:
    """Persist the CVE database to disk.

    Args:
        database: List of CVE entries to save.
    """
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    with open(CVE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(database, f, indent=2)


@tool
def lookup_similar_cves(
    vulnerability_description: str,
    vulnerability_category: str,
) -> list[dict[str, Any]]:
    """Query the local CVE database for known exploits similar to a detected vulnerability.

    This tool searches a locally-stored CVE database using keyword matching to find
    CVEs with similar characteristics to the provided vulnerability. This helps assess
    real-world exploitability by finding precedent in known attack patterns.

    Args:
        vulnerability_description: Description of the detected vulnerability to search for.
        vulnerability_category: The OWASP category or type of the vulnerability.

    Returns:
        A list of matching CVE entries, each containing:
            - cve_id: The CVE identifier
            - description: Description of the CVE
            - severity: Severity level
            - cvss: CVSS score
            - exploit_complexity: How complex the exploit is
            - relevance_score: How relevant this CVE is to the query (0-100)
    """
    database: list[dict[str, Any]] = _load_cve_database()
    query_terms: list[str] = (vulnerability_description + " " + vulnerability_category).lower().split()

    results: list[dict[str, Any]] = []

    for cve in database:
        score: int = 0
        cve_keywords: list[str] = cve.get("keywords", [])
        cve_text: str = (cve.get("description", "") + " " + cve.get("category", "")).lower()

        for term in query_terms:
            if len(term) < 3:
                continue
            for keyword in cve_keywords:
                if term in keyword or keyword in term:
                    score += 15
            if term in cve_text:
                score += 10

        if score > 0:
            results.append({
                "cve_id": cve["cve_id"],
                "description": cve["description"],
                "severity": cve["severity"],
                "cvss": cve["cvss"],
                "exploit_complexity": cve["exploit_complexity"],
                "relevance_score": min(score, 100),
            })

    results.sort(key=lambda x: x["relevance_score"], reverse=True)
    return results[:5]
