import subprocess
import json
import os
from typing import List, Dict, Any

def run_semgrep(target_dir: str) -> List[Dict[str, Any]]:
    """
    Runs Semgrep against a target directory and returns parsed findings.
    """
    try:
        # Run semgrep with auto config and json output
        # Using subprocess to run the CLI tool directly.
        # Ensure semgrep is installed and available in PATH.
        print(f"Running Semgrep on {target_dir}...")
        result = subprocess.run(
            [
                "semgrep", "scan", "--config", "auto", "--json", "--jobs", "4",
                "--exclude", "venv", "--exclude", "node_modules", "--exclude", ".git",
                "--exclude", "build", "--exclude", "dist",
                target_dir
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False # Semgrep returns non-zero if findings are found, so we don't check=True
        )
        
        output = result.stdout
        if not output:
            print("Error: Semgrep produced no output.")
            print(result.stderr)
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            print("Failed to parse Semgrep JSON output.")
            return []

        parsed_findings = []
        for finding in data.get("results", []):
            severity = finding.get("extra", {}).get("severity", "INFO")
            
            # Map severity to a base score
            if severity == "ERROR":
                severity_score = 1.0
            elif severity == "WARNING":
                severity_score = 0.5
            else:
                severity_score = 0.1

            file_path = finding.get("path")
            start_line = finding.get("start", {}).get("line")
            end_line = finding.get("end", {}).get("line", start_line)
            
            # Manually extract the snippet from the file to bypass a Semgrep Windows bug 
            # where extra.lines just outputs "requires login".
            snippet = ""
            try:
                if os.path.isabs(file_path):
                    actual_path = file_path
                else:
                    # Resolve relative to the target_dir
                    actual_path = os.path.normpath(os.path.join(target_dir, file_path))
                    
                with open(actual_path, "r", encoding="utf-8") as f:
                    file_lines = f.readlines()
                    if start_line and end_line and start_line <= len(file_lines):
                        # Line numbers are 1-indexed
                        snippet_lines = file_lines[start_line-1:end_line]
                        snippet = "".join(snippet_lines).strip()
            except Exception as e:
                print(f"Could not read snippet from file {file_path}: {e}")
                snippet = finding.get("extra", {}).get("lines", "")

            parsed_findings.append({
                "id": finding.get("check_id"),
                "file": file_path,
                "line": start_line,
                "message": finding.get("extra", {}).get("message"),
                "severity": severity,
                "severity_score": severity_score,
                "snippet": snippet
            })
            
        return parsed_findings
        
    except Exception as e:
        print(f"Error running Semgrep: {e}")
        return []

if __name__ == "__main__":
    # Simple test
    findings = run_semgrep(".")
    print(f"Found {len(findings)} issues.")
