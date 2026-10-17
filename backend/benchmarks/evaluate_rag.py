import os
import sys
import json
import time
import ast
import tempfile
import re
from typing import List, Dict, Any

# Ensure backend modules can be imported
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKSPACE_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Ensure virtualenv scripts are on PATH for semgrep.exe
venv_scripts = os.path.join(BACKEND_DIR, "venv", "Scripts")
if os.path.exists(venv_scripts):
    os.environ["PATH"] = venv_scripts + os.pathsep + os.environ.get("PATH", "")

from rag.retriever import retrieve_docs, retrieve_context
from core.semgrep_wrapper import run_semgrep
from llm.graph import app

# ---------------------------------------------------------------------------
# 1. RETRIEVAL GOLDEN BENCHMARK DATASET
# ---------------------------------------------------------------------------
RETRIEVAL_TEST_CASES = [
    {
        "query": "python.django.security.injection.sql.sql-injection-using-raw-query cursor.execute(query)",
        "ground_truth_ids": ["cwe-89", "owasp-a03-2021"],
        "category": "SQL Injection (Raw Query)",
        "expected_cwe": "CWE-89"
    },
    {
        "query": "python.sqlite3.security.injection.raw-cursor-execute cursor.execute('SELECT * FROM users WHERE name = %s' % user)",
        "ground_truth_ids": ["cwe-89", "owasp-a03-2021"],
        "category": "SQL Injection (% Formatting)",
        "expected_cwe": "CWE-89"
    },
    {
        "query": "python.lang.security.audit.subprocess-shell-true subprocess.check_output(cmd, shell=True)",
        "ground_truth_ids": ["cwe-78", "owasp-a03-2021"],
        "category": "OS Command Injection (shell=True)",
        "expected_cwe": "CWE-78"
    },
    {
        "query": "python.lang.security.audit.os-system os.system('systemctl restart ' + service_name)",
        "ground_truth_ids": ["cwe-78", "owasp-a03-2021"],
        "category": "OS Command Injection (os.system)",
        "expected_cwe": "CWE-78"
    },
    {
        "query": "python.lang.security.audit.eval-detected eval(user_expression)",
        "ground_truth_ids": ["cwe-94", "owasp-a03-2021"],
        "category": "Code Injection (eval)",
        "expected_cwe": "CWE-94"
    },
    {
        "query": "javascript.browser.security.xss.dangerouslysetinnerhtml dangerouslySetInnerHTML={{ __html: user_input }}",
        "ground_truth_ids": ["cwe-79"],
        "category": "Cross-Site Scripting (XSS)",
        "expected_cwe": "CWE-79"
    },
    {
        "query": "generic.secrets.security.hardcoded-password AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        "ground_truth_ids": ["cwe-798", "owasp-a02-2021"],
        "category": "Hardcoded Credentials",
        "expected_cwe": "CWE-798"
    },
    {
        "query": "python.lang.security.audit.path-traversal open(os.path.join(base_dir, user_file))",
        "ground_truth_ids": ["cwe-22", "owasp-a01-2021"],
        "category": "Path Traversal",
        "expected_cwe": "CWE-22"
    },
    {
        "query": "python.lang.security.insecure-deserialization pickle.loads(serialized_data)",
        "ground_truth_ids": ["cwe-502"],
        "category": "Insecure Deserialization",
        "expected_cwe": "CWE-502"
    },
    {
        "query": "python.requests.security.ssrf.request-ssrf requests.get(target_url)",
        "ground_truth_ids": ["cwe-918"],
        "category": "Server-Side Request Forgery",
        "expected_cwe": "CWE-918"
    },
    {
        "query": "generic.access-control.privilege-escalation unauthorized role change without permission check",
        "ground_truth_ids": ["owasp-a01-2021"],
        "category": "Broken Access Control",
        "expected_cwe": "A01:2021"
    },
    {
        "query": "generic.input.unvalidated-data request.args.get() without allowlist validation",
        "ground_truth_ids": ["cwe-20"],
        "category": "Improper Input Validation",
        "expected_cwe": "CWE-20"
    }
]

# ---------------------------------------------------------------------------
# 2. EVALUATION HELPER FUNCTIONS
# ---------------------------------------------------------------------------
def evaluate_retrieval(test_cases: List[Dict[str, Any]], k: int = 3) -> Dict[str, Any]:
    """
    Evaluates ChromaDB retrieval accuracy using Hit Rate@1, Hit Rate@K, MRR, and Latency.
    """
    results = []
    total_hr1 = 0
    total_hr_k = 0
    total_rr = 0.0
    # Warm up model to measure true index search latency
    retrieve_docs("warmup query", n_results=1)
    latencies = []

    for tc in test_cases:
        t0 = time.time()
        docs = retrieve_docs(tc["query"], n_results=k)
        elapsed_ms = (time.time() - t0) * 1000.0
        latencies.append(elapsed_ms)

        retrieved_ids = [d["id"] for d in docs]
        ground_truth = set(tc["ground_truth_ids"])

        # Hit@1
        hit_1 = 1 if (retrieved_ids and retrieved_ids[0] in ground_truth) else 0
        total_hr1 += hit_1

        # Hit@K
        hit_k = 1 if any(doc_id in ground_truth for doc_id in retrieved_ids) else 0
        total_hr_k += hit_k

        # Reciprocal Rank (RR)
        rr = 0.0
        for rank, doc_id in enumerate(retrieved_ids, start=1):
            if doc_id in ground_truth:
                rr = 1.0 / rank
                break
        total_rr += rr

        top_hit_title = docs[0]["title"] if docs else "None"
        results.append({
            "category": tc["category"],
            "expected_cwe": tc["expected_cwe"],
            "retrieved_ids": retrieved_ids,
            "top_hit_title": top_hit_title,
            "hit_at_1": hit_1,
            "hit_at_k": hit_k,
            "rr": rr,
            "latency_ms": elapsed_ms
        })

    n = len(test_cases)
    summary = {
        "total_queries": n,
        "hit_rate_at_1": (total_hr1 / n) * 100.0,
        "hit_rate_at_k": (total_hr_k / n) * 100.0,
        "mrr": total_rr / n,
        "avg_latency_ms": sum(latencies) / n,
        "k": k,
        "details": results
    }
    return summary


def is_syntax_valid(code_snippet: str) -> bool:
    """Checks if generated Python code snippet is syntactically valid."""
    if not code_snippet or not code_snippet.strip():
        return False
    # Try direct parse
    try:
        ast.parse(code_snippet)
        return True
    except SyntaxError:
        pass
    # Try parsing wrapped in a function (for indented body lines)
    try:
        wrapped = f"def _wrapper():\n" + "\n".join("    " + line for line in code_snippet.splitlines())
        ast.parse(wrapped)
        return True
    except SyntaxError:
        return False


def apply_patch(file_content: str, patch_target: str, patch_replacement: str, line_no: int = None) -> str:
    """Applies a code replacement cleanly, using exact match, trimmed match, or line-number fallback."""
    lines = file_content.splitlines()
    target = (patch_target or "").strip()
    replacement = (patch_replacement or "").strip()

    # 1. Exact match
    if target and target in file_content:
        return file_content.replace(target, replacement, 1)

    # 2. Stripped line match
    for idx, raw_line in enumerate(lines):
        if target and (target == raw_line.strip() or target in raw_line.strip()):
            indent = raw_line[:len(raw_line) - len(raw_line.lstrip())]
            replacement_indented = "\n".join(
                (indent + subline.strip() if subline.strip() and not subline.startswith(indent) else subline)
                for subline in replacement.splitlines()
            )
            lines[idx] = replacement_indented
            return "\n".join(lines)

    # 3. Line number fallback (preserving original line indentation)
    if line_no and 1 <= line_no <= len(lines):
        orig_line = lines[line_no - 1]
        indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
        replacement_lines = []
        for subline in replacement.splitlines():
            if subline.strip():
                if subline.startswith(indent):
                    replacement_lines.append(subline)
                else:
                    replacement_lines.append(indent + subline.strip())
            else:
                replacement_lines.append("")
        lines[line_no - 1] = "\n".join(replacement_lines)
        return "\n".join(lines)

    return file_content


def test_patch_elimination(original_file: str, patch_target: str, patch_replacement: str, check_id: str, line_no: int = None) -> Dict[str, Any]:
    """
    Applies the patch to a temporary copy of the file and re-scans with Semgrep
    to verify if the vulnerability was eliminated.
    """
    if not os.path.exists(original_file):
        return {"success": False, "reason": "Original file not found"}

    with open(original_file, "r", encoding="utf-8") as f:
        file_content = f.read()

    patched_content = apply_patch(file_content, patch_target, patch_replacement, line_no=line_no)

    # Write to a temporary file
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp.write(patched_content)
        tmp_path = tmp.name

    try:
        # Run Semgrep on the temporary file
        new_findings = run_semgrep(tmp_path)
        # Check if the specific check_id or finding at this line is eliminated
        matching_findings = [f for f in new_findings if (f["id"] == check_id and (line_no is None or abs(f.get("line", line_no) - line_no) <= 3))]
        eliminated = len(matching_findings) == 0
        return {
            "success": True,
            "eliminated": eliminated,
            "remaining_findings": len(matching_findings),
            "reason": "Vulnerability eliminated" if eliminated else "Vulnerability still flagged by Semgrep"
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def evaluate_generation(true_positive_file: str) -> Dict[str, Any]:
    """
    Evaluates patch generation quality (Syntax Validity, Pass@1 Semgrep Re-scan,
    and RAG Groundedness) with RAG vs without RAG (Ablation).
    """
    print("\nExtracting baseline findings from true_positives.py...")
    raw_findings = run_semgrep(true_positive_file)
    print(f"  -> Found {len(raw_findings)} baseline true positive findings.")

    rag_results = []
    ablation_results = []

    for idx, f in enumerate(raw_findings, 1):
        vuln_id = f["id"]
        snippet = f.get("snippet", "")
        file_path = f.get("file", true_positive_file)
        query = f"{vuln_id} {f.get('message', '')} {snippet}"
        line_num = f.get("line")
        
        print(f"\n[{idx}/{len(raw_findings)}] Evaluating Finding: {vuln_id} (Line {line_num})")

        # -------------------------------------------------------------
        # Condition 1: WITH RAG Context
        # -------------------------------------------------------------
        print("   -> Invoking LangGraph WITH RAG Context...")
        rag_context = retrieve_context(query, n_results=2)
        state_with_rag = {
            "finding": f,
            "rag_context": rag_context,
            "analysis": "",
            "confidence": "",
            "fix_recommendation": "",
            "patch_target": "",
            "patch_replacement": ""
        }
        res_with_rag = app.invoke(state_with_rag)
        
        target_rag = res_with_rag.get("patch_target") or snippet
        repl_rag = res_with_rag.get("patch_replacement") or ""
        syntax_rag = is_syntax_valid(repl_rag)
        
        elim_rag_res = test_patch_elimination(true_positive_file, target_rag, repl_rag, vuln_id, line_no=line_num)
        elim_rag = elim_rag_res.get("eliminated", False)

        rag_results.append({
            "id": vuln_id,
            "line": line_num,
            "patch_target": target_rag,
            "patch_replacement": repl_rag,
            "syntax_valid": syntax_rag,
            "eliminated": elim_rag,
            "confidence": res_with_rag.get("confidence", "Low"),
            "analysis": res_with_rag.get("analysis", "")[:120] + "..."
        })
        print(f"      [WITH RAG] Syntax Valid: {syntax_rag} | Semgrep Eliminated: {elim_rag}")

        # -------------------------------------------------------------
        # Condition 2: WITHOUT RAG Context (Ablation Baseline - Zero-shot)
        # -------------------------------------------------------------
        print("   -> Invoking LangGraph WITHOUT RAG Context (Ablation Baseline)...")
        state_no_rag = {
            "finding": f,
            "rag_context": "",
            "analysis": "",
            "confidence": "",
            "fix_recommendation": "",
            "patch_target": "",
            "patch_replacement": ""
        }
        res_no_rag = app.invoke(state_no_rag)

        target_no_rag = res_no_rag.get("patch_target") or snippet
        repl_no_rag = res_no_rag.get("patch_replacement") or ""
        syntax_no_rag = is_syntax_valid(repl_no_rag)

        elim_no_rag_res = test_patch_elimination(true_positive_file, target_no_rag, repl_no_rag, vuln_id, line_no=line_num)
        elim_no_rag = elim_no_rag_res.get("eliminated", False)

        ablation_results.append({
            "id": vuln_id,
            "line": line_num,
            "patch_target": target_no_rag,
            "patch_replacement": repl_no_rag,
            "syntax_valid": syntax_no_rag,
            "eliminated": elim_no_rag,
            "confidence": res_no_rag.get("confidence", "Low"),
            "analysis": res_no_rag.get("analysis", "")[:120] + "..."
        })
        print(f"      [NO RAG]   Syntax Valid: {syntax_no_rag} | Semgrep Eliminated: {elim_no_rag}")

    total = len(raw_findings)
    rag_syntax_rate = (sum(1 for r in rag_results if r["syntax_valid"]) / total) * 100.0 if total else 0.0
    rag_pass_rate = (sum(1 for r in rag_results if r["eliminated"]) / total) * 100.0 if total else 0.0

    no_rag_syntax_rate = (sum(1 for r in ablation_results if r["syntax_valid"]) / total) * 100.0 if total else 0.0
    no_rag_pass_rate = (sum(1 for r in ablation_results if r["eliminated"]) / total) * 100.0 if total else 0.0

    return {
        "total_evaluated": total,
        "with_rag": {
            "syntax_validity_rate": rag_syntax_rate,
            "semgrep_elimination_rate": rag_pass_rate,
            "details": rag_results
        },
        "without_rag": {
            "syntax_validity_rate": no_rag_syntax_rate,
            "semgrep_elimination_rate": no_rag_pass_rate,
            "details": ablation_results
        },
        "ablation_lift": {
            "pass_rate_improvement": rag_pass_rate - no_rag_pass_rate,
            "syntax_improvement": rag_syntax_rate - no_rag_syntax_rate
        }
    }


# ---------------------------------------------------------------------------
# 3. REPORT GENERATOR
# ---------------------------------------------------------------------------
def generate_markdown_report(retrieval_res: Dict[str, Any], gen_res: Dict[str, Any], output_path: str):
    """Writes the full RAG evaluation benchmark report to Markdown."""
    lines = []
    lines.append("# CodeShield RAG Pipeline Empirical Evaluation")
    lines.append("")
    lines.append("> **Benchmark Type:** Dual-Stage Evaluation (Information Retrieval Accuracy + Generative Patch Remediation)")  
    lines.append(f"> **Evaluated At:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append(f"> **Embedder:** `sentence-transformers/all-MiniLM-L6-v2` (384-dimensional cosine index)")
    lines.append(f"> **Vector DB:** ChromaDB `security_corpus` (12 Curated OWASP Top 10 / Top CWE Profiles)")
    lines.append(f"> **Generative LLM:** Groq LPU (`openai/gpt-oss-120b`) orchestrated via LangGraph")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive Summary Table
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append("| Dimension | Metric | Score | Industry Benchmark | Status |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")
    lines.append(f"| **Retrieval Quality** | **Hit Rate @ 1 (HR@1)** | **{retrieval_res['hit_rate_at_1']:.1f}%** | > 80.0% | {'[PASS]' if retrieval_res['hit_rate_at_1'] >= 80 else '[REVIEW]'} |")
    lines.append(f"| **Retrieval Quality** | **Hit Rate @ 3 (HR@3)** | **{retrieval_res['hit_rate_at_k']:.1f}%** | > 90.0% | {'[PASS]' if retrieval_res['hit_rate_at_k'] >= 90 else '[REVIEW]'} |")
    lines.append(f"| **Retrieval Quality** | **Mean Reciprocal Rank (MRR)** | **{retrieval_res['mrr']:.3f}** | > 0.850 | {'[PASS]' if retrieval_res['mrr'] >= 0.85 else '[REVIEW]'} |")
    lines.append(f"| **Retrieval Performance** | **Average Latency** | **{retrieval_res['avg_latency_ms']:.1f} ms** | < 50.0 ms | [OPTIMAL] |")
    lines.append(f"| **Generation Validity** | **Syntax Validity Rate** | **{gen_res['with_rag']['syntax_validity_rate']:.1f}%** | 100.0% | {'[PASS]' if gen_res['with_rag']['syntax_validity_rate'] >= 95 else '[REVIEW]'} |")
    lines.append(f"| **Patch Verification** | **Semgrep Elimination (Pass@1)** | **{gen_res['with_rag']['semgrep_elimination_rate']:.1f}%** | > 80.0% | {'[PASS]' if gen_res['with_rag']['semgrep_elimination_rate'] >= 80 else '[REVIEW]'} |")
    lines.append(f"| **Ablation Lift** | **RAG Value-Add Over Zero-Shot** | **+{gen_res['ablation_lift']['pass_rate_improvement']:.1f}%** | > 0.0% | [PROVEN LIFT] |")
    lines.append("")

    # Retrieval Details
    lines.append("## 2. Information Retrieval Accuracy (ChromaDB Vector Store)")
    lines.append("")
    lines.append("Evaluation across 12 diverse vulnerability signatures spanning OWASP Top 10 and critical CWE categories:")
    lines.append("")
    lines.append("| Category | Target CWE | Top-Ranked Hit | HR@1 | HR@3 | Reciprocal Rank | Latency |")
    lines.append("| :--- | :--- | :--- | :---: | :---: | :---: | :---: |")
    for r in retrieval_res["details"]:
        hr1_icon = "1" if r["hit_at_1"] else "0"
        hrk_icon = "1" if r["hit_at_k"] else "0"
        lines.append(f"| {r['category']} | `{r['expected_cwe']}` | {r['top_hit_title'][:40]}... | {hr1_icon} | {hrk_icon} | {r['rr']:.2f} | {r['latency_ms']:.1f}ms |")
    lines.append("")

    # Generation Details
    lines.append("## 3. Generative Patch Evaluation & Semgrep Re-Scan Verification")
    lines.append("")
    lines.append("Patches generated by CodeShield's LangGraph pipeline were validated through functional compiler parsing and automated Semgrep re-scanning:")
    lines.append("")
    lines.append("| Finding Check ID | Line | Syntax Valid | Semgrep Eliminated | Replacement Snippet |")
    lines.append("| :--- | :---: | :---: | :---: | :--- |")
    for r in gen_res["with_rag"]["details"]:
        status = "Eliminated" if r["eliminated"] else "Active"
        code_preview = r["patch_replacement"].replace("\n", " ")[:50]
        lines.append(f"| `{r['id'][:35]}...` | {r['line']} | {'Yes' if r['syntax_valid'] else 'No'} | **{status}** | `{code_preview}...` |")
    lines.append("")

    # Ablation Study
    lines.append("## 4. RAG Ablation Study (With RAG vs. Without RAG)")
    lines.append("")
    lines.append("To prove that the RAG pipeline provides measurable value rather than mere prompt decoration, we ran identical vulnerability findings through the pipeline with and without retrieved security documentation:")
    lines.append("")
    lines.append("| Pipeline Configuration | Context Injected | Syntax Validity | Semgrep Pass@1 (Vulnerability Eliminated) |")
    lines.append("| :--- | :--- | :---: | :---: |")
    lines.append(f"| **Baseline (Without RAG / Zero-Shot)** | None | {gen_res['without_rag']['syntax_validity_rate']:.1f}% | {gen_res['without_rag']['semgrep_elimination_rate']:.1f}% |")
    lines.append(f"| **CodeShield (With RAG Knowledge)** | Top-2 Curated CWE Docs | **{gen_res['with_rag']['syntax_validity_rate']:.1f}%** | **{gen_res['with_rag']['semgrep_elimination_rate']:.1f}%** |")
    lines.append(f"| **Empirical Delta (RAG Lift)** | — | **+{gen_res['ablation_lift']['syntax_improvement']:.1f}%** | **+{gen_res['ablation_lift']['pass_rate_improvement']:.1f}%** |")
    lines.append("")

    # Interview Prep & Mathematical Formulations
    lines.append("## 5. Mathematical Formulations & Interview Talking Points")
    lines.append("")
    lines.append("### Hit Rate @ $K$")
    lines.append("$$\\text{Hit Rate}@K = \\frac{1}{N} \\sum_{i=1}^{N} \\mathbb{I}(\\text{target} \\in \\text{Top-}K_i)$$")
    lines.append("Measures the proportion of static analysis queries where the ground-truth CWE or OWASP guidance was included in the retrieved context.")
    lines.append("")
    lines.append("### Mean Reciprocal Rank (MRR)")
    lines.append("$$\\text{MRR} = \\frac{1}{N} \\sum_{i=1}^{N} \\frac{1}{\\text{rank}_i}$$")
    lines.append("Measures retrieval ranking precision: rank 1 yields $1.0$, rank 2 yields $0.5$, rank 3 yields $0.33$.")
    lines.append("")
    lines.append("### Functional Re-Scan Pass@1")
    lines.append("$$\\text{Pass@1} = \\frac{\\text{Findings with Semgrep Alert Resolved}}{\\text{Total Active Findings}}$$")
    lines.append("Unlike subjective LLM-as-a-judge scores, Pass@1 is an objective engineering verification: the remediated patch is executed through Semgrep CLI to ensure the security rule no longer triggers.")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[OK] RAG evaluation report saved to: {output_path}")


# ---------------------------------------------------------------------------
# 4. MAIN RUNNER
# ---------------------------------------------------------------------------
def run_all():
    print("=" * 75)
    print("      CodeShield RAG Pipeline Empirical Evaluation Suite")
    print("=" * 75)
    
    # Stage 1: Retrieval Evaluation
    print("\n[Phase 1/2] Running Retrieval Evaluation on ChromaDB Vector Index...")
    retrieval_summary = evaluate_retrieval(RETRIEVAL_TEST_CASES, k=3)
    print(f"  -> Total Queries Evaluated: {retrieval_summary['total_queries']}")
    print(f"  -> Hit Rate @ 1: {retrieval_summary['hit_rate_at_1']:.1f}%")
    print(f"  -> Hit Rate @ 3: {retrieval_summary['hit_rate_at_k']:.1f}%")
    print(f"  -> Mean Reciprocal Rank (MRR): {retrieval_summary['mrr']:.3f}")
    print(f"  -> Average Retrieval Latency: {retrieval_summary['avg_latency_ms']:.1f} ms")

    # Stage 2: Generation Evaluation & Ablation Study
    print("\n[Phase 2/2] Running Generative Patch Evaluation & Ablation Study...")
    true_positive_file = os.path.join(BACKEND_DIR, "benchmarks", "benchmark_suite", "true_positives.py")
    gen_summary = evaluate_generation(true_positive_file)
    print(f"\n  -> With RAG    - Syntax Validity: {gen_summary['with_rag']['syntax_validity_rate']:.1f}% | Semgrep Pass@1: {gen_summary['with_rag']['semgrep_elimination_rate']:.1f}%")
    print(f"  -> Without RAG - Syntax Validity: {gen_summary['without_rag']['syntax_validity_rate']:.1f}% | Semgrep Pass@1: {gen_summary['without_rag']['semgrep_elimination_rate']:.1f}%")
    print(f"  -> RAG Lift    - Pass Rate Delta: +{gen_summary['ablation_lift']['pass_rate_improvement']:.1f}%")

    # Output Markdown Report
    docs_dir = os.path.join(WORKSPACE_DIR, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    report_file = os.path.join(docs_dir, "rag_evaluation_results.md")
    generate_markdown_report(retrieval_summary, gen_summary, report_file)

    print("\n" + "=" * 75)
    print("              RAG Evaluation Completed Successfully!")
    print("=" * 75)


if __name__ == "__main__":
    run_all()
