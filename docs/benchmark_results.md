# CodeShield Empirical Benchmark Report: False Positive Reduction

**Date:** 2026-09-03 11:31:56  
**Evaluation Environment:** Python 3.13, Semgrep 1.174.0, Tree-sitter (Python AST), LangGraph Multi-Agent RAG  
**Test Suite:** `backend/benchmarks/benchmark_suite/`

---

## 1. Executive Summary

In a controlled benchmark evaluation of vulnerability patterns across web applications:
* **False Positive Reduction Rate:** **100.0%** of non-exploitable and dead-code alerts were successfully filtered out.
* **Alert Noise Reduction:** Developer alert volume was reduced by **68.8%** (from 16 raw alerts down to 5 verified actionable findings).
* **True Positive Retention Rate:** **100.0%** (zero valid, reachable vulnerabilities were dropped).

---

## 2. Key Metrics Table

| Metric | Baseline (Raw Semgrep) | CodeShield (AST + AI) | Impact |
| :--- | :---: | :---: | :---: |
| **Total Alerts Triaged** | `16` | `5` | **68.8% noise reduction** |
| **Dead-Code False Positives** | `8` | `0` | **100.0% eliminated via AST** |
| **Sanitized Input False Positives** | `3` | `0` | **100.0% filtered via Agentic RAG** |
| **Actionable True Positives Retained** | `5` | `5` | **100.0% safety retention** |

---

## 3. Evaluation Methodology

### A. Test Suite Composition
1. **`true_positives.py` (5 cases):** Live endpoints invoking SQL injection, OS command injection, path traversal, arbitrary code execution, and weak cryptography with unsanitized user inputs.
2. **`dead_code_vulns.py` (8 cases):** Vulnerability patterns located in orphaned functions, deprecated modules, and uninstantiated classes with zero callers across the codebase.
3. **`sanitized_vulns.py` (3 cases):** Syntactic pattern matches that trigger traditional SAST regex/AST rules, but where parameters are strictly sanitized (e.g., `int()` casting, `shlex.quote()`, or `os.path.basename()` traversal prevention).

### B. Two-Stage Filtering Pipeline
1. **Stage 1 (Tree-sitter AST Reachability):**
   - Parses the project's Abstract Syntax Tree.
   - Calculates call occurrences for every function defining a finding.
   - Downgrades dead code to a reachability score of `0.2` and combined `risk_score < 40`, instantly eliminating dead-code alerts from high-priority triage.
2. **Stage 2 (LangGraph Multi-Agent Triage):**
   - Queries ChromaDB for official OWASP/CWE remediation context.
   - Analyst Agent evaluates contextual exploitability (detecting input validation and variable constraints).
   - Generates confidence scores and deterministic patches for genuine vulnerabilities while filtering out contextual false alarms.

---

## 4. How to Reproduce This Benchmark

Run the automated evaluation runner from the project root:
```powershell
.\backend\venv\Scripts\python.exe backend\benchmarks\evaluate.py
```
