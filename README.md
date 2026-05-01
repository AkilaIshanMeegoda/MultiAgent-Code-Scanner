# 🔒 Code Security Auditor — Multi-Agent System (MAS)

**SE4010 — Contemporary Software Engineering Technologies (CTSE) — Assignment 2**

A locally-hosted Multi-Agent System for automated code security auditing, built with LangGraph orchestration and Ollama LLMs. The system scans source code projects for OWASP Top 10 vulnerabilities, assesses exploitability against known CVEs, and generates professional penetration-testing-style reports.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Multi-Agent Pipeline](#multi-agent-pipeline)
3. [Agent Descriptions](#agent-descriptions)
4. [Custom Tool Descriptions](#custom-tool-descriptions)
5. [State Management](#state-management)
6. [Observability & Logging](#observability--logging)
7. [Testing & Evaluation](#testing--evaluation)
8. [Setup & Installation](#setup--installation)
9. [How to Run](#how-to-run)
10. [Project Structure](#project-structure)
11. [Configuration](#configuration)
12. [How to Change the LLM Model](#how-to-change-the-llm-model)
13. [Assignment Criteria Mapping](#assignment-criteria-mapping)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LangGraph Orchestrator                        │
│                  (Sequential Pipeline + Conditional Routing)     │
│                                                                  │
│  ┌──────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
│  │ CodeScanner  │──▶│  VulnDetector   │──▶│ ExploitAssessor  │  │
│  │    Agent      │   │     Agent        │   │      Agent       │  │
│  └──────────────┘   └─────────────────┘   └──────────────────┘  │
│         │                    │                      │            │
│         ▼                    ▼                      ▼            │
│  ┌──────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
│  │ code_reader  │   │ vuln_scanner    │   │  cve_lookup      │  │
│  │    (Tool 1)  │   │    (Tool 2)     │   │    (Tool 3)      │  │
│  └──────────────┘   └─────────────────┘   └──────────────────┘  │
│                                                                  │
│                    ┌──────────────────┐                          │
│                    │  SecurityReport  │                          │
│                    │      Agent       │                          │
│                    └──────────────────┘                          │
│                            │                                     │
│                            ▼                                     │
│                    ┌──────────────────┐                          │
│                    │ report_generator │                          │
│                    │    (Tool 4)      │                          │
│                    └──────────────────┘                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Shared Global State (TypedDict)             │   │
│  │  session_id, code_structure, vulnerabilities,            │   │
│  │  exploitability_assessments, full_report, agent_traces   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         Ollama LLM (llama3.1:8b / llama3.2:3b)          │   │
│  │              Running locally on localhost:11434           │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Key Technology Stack:**

- **LangGraph** — StateGraph-based orchestration with conditional edges for error routing
- **LangChain + ChatOllama** — Interface to locally-hosted Ollama LLMs
- **Ollama** — Local LLM runtime (llama3.1:8b or llama3.2:3b)
- **FastAPI + Uvicorn** — REST API backend with SSE streaming for real-time progress
- **React 19 + Vite** — Professional dark-themed frontend dashboard
- **Pydantic/TypedDict** — Strict state schema for inter-agent communication
- **Rich** — Terminal UI with colored panels and tables
- **pytest** — Comprehensive testing framework

---

## Multi-Agent Pipeline

The system uses a **sequential pipeline** implemented via LangGraph's `StateGraph`:

```
START → CodeScannerAgent → VulnerabilityDetectorAgent → ExploitabilityAssessorAgent → SecurityReportAgent → END
                ↓                    ↓                           ↓
          (error_handler)     (error_handler)              (error_handler)
```

**Conditional Routing:**

- After each agent, a routing function checks the state's `status` field
- If `status == "error"`, the pipeline routes to the `handle_error` node
- If CodeScanner finds no files, it skips directly to SecurityReportAgent
- The `agent_traces` field uses LangGraph's `Annotated[list, operator.add]` reducer to accumulate traces across all agents

---

## Agent Descriptions

### Agent 1: CodeScannerAgent (`src/agents/code_scanner.py`)

**Purpose:** Reads all source files, identifies languages/frameworks, maps data flows and entry points.

**Workflow:**

1. Calls `read_project_files` tool to scan the project directory
2. Sends code summary to LLM for structural analysis (frameworks, data flows, entry points)
3. Parses LLM JSON response and populates state with `code_structure`, `data_flows`, `entry_points`

**LLM Prompt:** Constrained system prompt requiring JSON-only output with specific schema for frameworks, data_flows, and entry_points arrays.

### Agent 2: VulnerabilityDetectorAgent (`src/agents/vulnerability_detector.py`)

**Purpose:** Scans code for OWASP Top 10 vulnerabilities using both automated regex patterns and LLM validation.

**Workflow:**

1. Calls `scan_code_for_vulnerabilities` tool for automated pattern matching
2. Sends tool results + code context to LLM for validation and enrichment
3. Merges tool findings with LLM-validated results
4. Builds severity summary and vulnerability location map

**Key Feature:** Dual-validation approach — automated scanning catches known patterns while LLM identifies subtle, context-dependent vulnerabilities.

### Agent 3: ExploitabilityAssessorAgent (`src/agents/exploitability_assessor.py`)

**Purpose:** Assesses real-world exploitability of each vulnerability, queries CVE database, and prioritizes findings.

**Workflow:**

1. Groups vulnerabilities by category
2. Calls `lookup_similar_cves` tool for each category to find related known CVEs
3. Sends vulnerabilities + CVE data to LLM for exploitability assessment
4. Builds risk matrix and priority ordering

**Key Feature:** Links detected vulnerabilities to real CVE entries, providing evidence-based risk assessment.

### Agent 4: SecurityReportAgent (`src/agents/security_report.py`)

**Purpose:** Generates a professional penetration-testing-style Markdown report.

**Workflow:**

1. Collects all data from previous agents (vulnerabilities, assessments, risk matrix)
2. Sends to LLM for executive summary, technical findings, remediation snippets, and roadmap
3. Calls `generate_security_report` tool to format and save the final Markdown report

**Output:** A complete security report with severity badges, OWASP categories, remediation code, and fix priority roadmap.

---

## Custom Tool Descriptions

### Tool 1: Code Reader (`src/tools/code_reader.py`)

**Function:** `read_project_files(project_path: str) -> dict`

Recursively reads all source code files from a project directory. Detects programming languages via file extension mapping. Skips binary files, `node_modules`, `.git`, `__pycache__`, etc. Returns file contents, language distribution, file list, and total line count.

**Key Features:**

- Supports 15+ languages (Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, etc.)
- Configurable `MAX_FILE_SIZE` (1MB) and `SKIP_DIRS` for performance
- Returns structured dict with `file_contents`, `languages`, `file_list`, `total_lines`, `language_distribution`

### Tool 2: Vulnerability Scanner (`src/tools/vulnerability_scanner.py`)

**Function:** `scan_code_for_vulnerabilities(file_contents: dict) -> list[dict]`

Regex-based OWASP Top 10 vulnerability pattern scanner. Each vulnerability pattern is mapped to an OWASP category with a pre-assigned CVSS score.

**Detected Categories:**
| OWASP Category | Patterns |
|---|---|
| A01: Broken Access Control | Command injection (`os.system`, `subprocess`), CORS misconfiguration |
| A02: Cryptographic Failures | Weak hashing (MD5/SHA1), hardcoded secrets/passwords/API keys |
| A03: Injection | SQL injection (f-strings, %-format, .format()), XSS, eval/exec, SSTI |
| A05: Security Misconfiguration | Debug mode, SSL verification disabled |
| A06: Vulnerable Components | Insecure deserialization (pickle, yaml.load) |
| A07: Authentication Failures | Plaintext password comparison, hardcoded credentials |
| A08: Data Integrity Failures | Unsafe YAML loading |
| A09: Logging Failures | Sensitive data in print/log statements |
| A10: SSRF | Unvalidated URL requests |

### Tool 3: CVE Lookup (`src/tools/cve_lookup.py`)

**Function:** `lookup_similar_cves(vulnerability_description: str, vulnerability_category: str) -> list[dict]`

Queries a local CVE database for vulnerabilities similar to the detected finding. Uses keyword matching with relevance scoring. Returns up to 5 results sorted by relevance.

**Features:**

- 20 built-in CVE entries covering major vulnerability categories
- Keyword-based matching with category boosting
- Relevance scoring (0.0–1.0) for prioritization
- Extensible via `data/cve_database.json`

### Tool 4: Report Generator (`src/tools/report_generator.py`)

**Function:** `generate_security_report(...) -> dict`

Generates a comprehensive Markdown security report with severity badges, OWASP categorization, remediation code snippets, and statistics. Saves the report to the target project's `security_reports/` directory.

**Report Sections:** Executive Summary, Severity Summary Table, Detailed Vulnerability Findings, Exploitability Assessments, Remediation Code Snippets, Fix Priority Roadmap, Statistics.

---

## State Management

The system uses a **shared global state** (`PipelineState` TypedDict) that flows through all agents:

```python
class PipelineState(TypedDict, total=False):
    session_id: str                          # Unique audit session ID
    project_path: str                        # Target project path
    started_at: str                          # ISO timestamp
    completed_at: str                        # ISO timestamp
    status: str                              # Current pipeline status
    code_structure: dict                     # Agent 1 output
    data_flows: list                         # Agent 1 output
    framework_info: dict                     # Agent 1 output
    entry_points: list                       # Agent 1 output
    vulnerabilities: list                    # Agent 2 output
    vulnerability_locations: dict            # Agent 2 output
    severity_summary: dict                   # Agent 2 output
    exploitability_assessments: list         # Agent 3 output
    priority_order: list                     # Agent 3 output
    risk_matrix: dict                        # Agent 3 output
    executive_summary: str                   # Agent 4 output
    technical_findings: str                  # Agent 4 output
    remediation_snippets: dict               # Agent 4 output
    fix_priority_roadmap: str                # Agent 4 output
    full_report: str                         # Agent 4 output
    agent_traces: Annotated[list, operator.add]  # Accumulated traces (reducer)
    current_agent: str                       # Currently executing agent
```

**State Flow Pattern:**

- Each agent receives the full accumulated state as input
- Each agent returns only the keys it modifies (update dict pattern)
- `agent_traces` uses LangGraph's `operator.add` reducer to automatically accumulate trace entries across all agents
- Error states propagate through conditional edges to the error handler

---

## Observability & Logging

**Module:** `src/observability.py`

- **AgentTracer** class tracks each agent's lifecycle: start time, tool calls, completion/error
- **Rich Console** panels display agent status with colored borders (green=success, red=error)
- **State Transition Logging** shows which state keys are passed between agents
- **Pipeline Summary Table** displays all agents' status, duration, and tool call count
- **File Logging** writes structured logs to `logs/` directory
- **Structured Agent Traces** stored in state for post-execution analysis

---

## Testing & Evaluation

**Test Suite:** `tests/test_agents.py` — **33 tests across 5 test classes**

| Test Class                     | Tests | What It Validates                                                                                                       |
| ------------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------------- |
| `TestCodeReaderTool`           | 6     | File reading, language detection, directory skipping, error handling                                                    |
| `TestVulnerabilityScannerTool` | 9     | SQL injection, secrets, command injection, deserialization, weak hashing, CVSS scores, clean code, multi-vuln detection |
| `TestCVELookupTool`            | 7     | CVE lookup for SQL/command injection/deserialization, result structure, sorting, max results, score bounds              |
| `TestReportGeneratorTool`      | 8     | Report generation, file saving, content sections, stats accuracy, empty vulns handling, Markdown format                 |
| `TestStateManagement`          | 3     | Initial state keys, state data preservation, session ID uniqueness                                                      |
| `TestLLMJudge`                 | 1     | LLM-as-a-judge evaluation (requires running Ollama, skipped in CI)                                                      |

**Run Tests:**

```bash
python -m pytest tests/test_agents.py -v --tb=short -k "not LLMJudge"
```

**LLM-as-a-Judge Evaluation:** The `TestLLMJudge` test sends a known-vulnerable code snippet to the LLM and evaluates whether it correctly identifies security issues. This provides an automated quality check on the LLM's security analysis capabilities.

---

## Setup & Installation

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- [Ollama](https://ollama.ai/) installed and running

### Steps

```bash
# 1. Clone the repository
git clone <repo-url>
cd Code-Security-Checker

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install frontend dependencies
cd frontend
npm install
cd ..

# 4. Pull the Ollama model
ollama pull llama3.2:3b
# OR for better results (requires 18+ GB RAM):
# ollama pull llama3.1:8b

# 5. Verify Ollama is running
curl http://localhost:11434/api/tags

# 6. Run tests
python -m pytest tests/test_agents.py -v -k "not LLMJudge"
```

---

## How to Run

### Option 1: Web Dashboard (Frontend + Backend)

**Terminal 1 — Start the Backend API:**

```bash
cd Code-Security-Checker
python -m uvicorn server:app --reload --port 8000
```

**Terminal 2 — Start the Frontend:**

```bash
cd Code-Security-Checker/frontend
npm run dev
```

Open **http://localhost:5173** in your browser. The dashboard provides:

- Real-time pipeline progress with SSE streaming
- Vulnerability table with severity badges
- Agent trace timeline
- Full Markdown report viewer
- Scan history
- Settings panel to change the Ollama model

### Option 2: CLI (Terminal Only)

```bash
# Scan a project
python main.py /path/to/your/project

# Scan the included sample vulnerable app
python main.py ./sample_vulnerable_app

# The report will be saved to:
# <project_path>/security_reports/security_report_<timestamp>.md
```

**Sample CLI Output:**

```
🔒 CODE SECURITY AUDITOR - Multi-Agent System
======================================================================
Pipeline: CodeScanner → VulnDetector → ExploitAssessor → ReportGen

✅ CodeScannerAgent    | 18.28s | 2 tools | Found 9 entry points
✅ VulnDetectorAgent   | 14.99s | 2 tools | 34 vulnerabilities
✅ ExploitAssessorAgent | 17.89s | 9 tools | Risk matrix built
✅ SecurityReportAgent  | 15.81s | 2 tools | Report generated

Severity: CRITICAL=17 | HIGH=10 | MEDIUM=4 | LOW=3
```

---

## Project Structure

```
Code-Security-Checker/
├── main.py                          # CLI entry point
├── server.py                        # FastAPI backend API (SSE, REST)
├── config.json                      # Model & Ollama configuration
├── requirements.txt                 # Python dependencies
├── README.md                        # This documentation
├── src/
│   ├── __init__.py
│   ├── config.py                    # Configuration loader
│   ├── state.py                     # Global state schema (TypedDict)
│   ├── pipeline.py                  # LangGraph orchestrator
│   ├── observability.py             # Logging, tracing, Rich UI
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── code_scanner.py          # Agent 1: Code structure analysis
│   │   ├── vulnerability_detector.py # Agent 2: OWASP vuln detection
│   │   ├── exploitability_assessor.py # Agent 3: CVE-based risk assessment
│   │   └── security_report.py       # Agent 4: Report generation
│   └── tools/
│       ├── __init__.py
│       ├── code_reader.py           # Tool 1: Project file reader
│       ├── vulnerability_scanner.py # Tool 2: Regex pattern scanner
│       ├── cve_lookup.py            # Tool 3: Local CVE database
│       └── report_generator.py      # Tool 4: Markdown report generator
├── frontend/                        # React + Vite web dashboard
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js               # Proxy /api → backend:8000
│   └── src/
│       ├── main.jsx                 # React entry point
│       ├── App.jsx                  # Dashboard component
│       └── index.css                # Dark-themed styles
├── tests/
│   ├── __init__.py
│   └── test_agents.py              # 33 comprehensive tests
├── sample_vulnerable_app/           # Intentionally vulnerable Flask app
│   ├── app.py                       # 15+ deliberate vulnerabilities
│   ├── config.py                    # Hardcoded secrets
│   └── database.py                  # SQL injection, unsafe YAML
├── data/
│   └── cve_database.json           # Extensible CVE database
└── logs/                           # Runtime log files
```

---

## Assignment Criteria Mapping

### 1. Problem Definition & Planning (10%)

- **Problem:** Manual code security auditing is slow, inconsistent, and error-prone. Organizations need automated, repeatable security scanning that covers OWASP Top 10 categories.
- **Solution:** A 4-agent pipeline that decomposes security auditing into specialized stages: code analysis → vulnerability detection → exploitability assessment → report generation.
- **Justification for MAS:** Each stage requires different expertise (code analysis vs. vulnerability patterns vs. CVE knowledge vs. report writing). Agents can be developed, tested, and improved independently.

### 2. Multi-Agent Architecture Design (15%)

- **Framework:** LangGraph `StateGraph` with `PipelineState` TypedDict
- **Orchestration:** Sequential pipeline with conditional error routing via `add_conditional_edges`
- **State Sharing:** Typed shared state with `operator.add` reducer for trace accumulation
- **Error Handling:** Each agent catches exceptions and sets `status="error"`; conditional edges route to error handler
- **Architecture Diagram:** See [System Architecture](#system-architecture) section

### 3. Custom Tool Development (10%)

- **4 custom tools** built as LangChain `@tool`-decorated functions:
  1. `read_project_files` — File system traversal with language detection
  2. `scan_code_for_vulnerabilities` — Regex-based OWASP pattern matching with CVSS scoring
  3. `lookup_similar_cves` — Local CVE database with keyword relevance scoring
  4. `generate_security_report` — Markdown report generation with severity badges

### 4. State Management & Observability (10%)

- **State:** `PipelineState` TypedDict with 22 fields covering all inter-agent data
- **Observability:** `AgentTracer` class with structured logging, Rich panels, state transition visualization, pipeline summary table, and file-based log persistence
- **Traceability:** Every tool call logged with input/output, every agent lifecycle tracked with duration and status

### 5. Testing & Evaluation Strategy (10%)

- **33 automated tests** across 5 test classes using pytest
- **Tool-level testing:** Each of the 4 tools has dedicated test class with edge cases
- **State management testing:** Validates state schema, data preservation, session uniqueness
- **LLM-as-a-Judge:** Automated evaluation of LLM security analysis quality
- **Integration testing:** Full pipeline execution against sample vulnerable app (demonstrated in [Usage](#usage))

### 6. Individual Agent Design (20% — 5% per agent)

- Each agent has a dedicated module with clear responsibilities
- Each agent uses a **constrained system prompt** to minimize hallucination (JSON-only output)
- Each agent calls at least one custom tool + the LLM
- Each agent returns a state update dict (not mutating state in place)
- See [Agent Descriptions](#agent-descriptions) for detailed workflow documentation

### 7. Individual Custom Tool (20% — 5% per tool)

- Each tool is a standalone module with `@tool` decorator
- Each tool has comprehensive input validation and error handling
- Each tool is independently testable (7-9 tests per tool)
- See [Custom Tool Descriptions](#custom-tool-descriptions) for detailed documentation

### 8. System Demonstration (5%)

- **Sample Vulnerable App:** `sample_vulnerable_app/` contains an intentionally vulnerable Flask application with 15+ deliberate security flaws
- **End-to-end execution:** Pipeline successfully detects 34 vulnerabilities (17 Critical, 10 High, 4 Medium, 3 Low)
- **Generated report:** Professional Markdown report with severity badges, OWASP categories, and remediation guidance
- **Rich terminal output:** Colored panels, state transitions, and pipeline summary table

---

## Configuration

Edit `config.json` to change settings:

```json
{
  "ollama_model": "llama3.2:3b",
  "ollama_base_url": "http://localhost:11434"
}
```

**Model Options:**

- `llama3.2:3b` — Requires ~4GB RAM, faster but less accurate
- `llama3.1:8b` — Requires ~18GB RAM, more accurate analysis

---

## How to Change the LLM Model

### Method 1: Via the Web UI (Recommended)

1. Open the frontend at **http://localhost:5173**
2. Click the **Settings** button (top-right)
3. Enter the new model name (e.g., `llama3.1:8b`)
4. Click **Save** — changes apply immediately to the next scan

### Method 2: Edit `config.json` Manually

1. Open `config.json` in the project root
2. Change the `"ollama_model"` value:
   ```json
   {
     "ollama_model": "llama3.1:8b"
   }
   ```
3. Restart the backend server if it's running

### Method 3: Pull and Use a Different Ollama Model

```bash
# Pull the new model
ollama pull <model-name>

# Example models that work well:
ollama pull llama3.1:8b        # Better accuracy, needs 18GB+ RAM
ollama pull llama3.2:3b        # Lighter, works on 6GB RAM
ollama pull codellama:7b       # Code-specialized model
ollama pull mistral:7b         # General purpose

# Then update config.json or use the Settings UI
```

> **Note:** Make sure the model is fully downloaded (`ollama list` to verify) before starting a scan.

---

_Built for SE4010 CTSE Assignment 2 — Multi-Agent System for Code Security Auditing_
