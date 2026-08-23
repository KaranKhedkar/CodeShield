import os
import sys

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from core.semgrep_wrapper import run_semgrep
from core.reachability import enhance_findings_with_risk
from rag.retriever import retrieve_context
from llm.analyzer import analyze_finding

def test_pipeline():
    target_dir = os.path.dirname(__file__)
    print(f"Target dir: {target_dir}")
    
    # Run semgrep
    print("Running semgrep...")
    findings = run_semgrep(target_dir)
    print(f"Found {len(findings)} findings.")
    
    # Reachability
    print("Calculating reachability...")
    findings = enhance_findings_with_risk(findings, target_dir)
    for f in findings:
        print(f"File: {f['file']}, Line: {f['line']}, Risk Score: {f['risk_score']}")
        
        query = f"{f['id']} {f.get('message', '')}"
        print(f"Retrieving context for query: {query}")
        rag_context = retrieve_context(query)
        print(f"Retrieved context length: {len(rag_context)}")
        
        print("Analyzing with LLM (may fail gracefully if Ollama is not running)...")
        res = analyze_finding(f, rag_context)
        print(f"LLM Result: {res}")
        print("-" * 50)

if __name__ == "__main__":
    test_pipeline()
