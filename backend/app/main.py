from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
import os
import sys
import concurrent.futures
import tempfile
import subprocess
import urllib.parse

# Import our core logic
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from .db.session import engine, Base, get_db
from .db import models
from core.semgrep_wrapper import run_semgrep
from core.reachability import enhance_findings_with_risk
from rag.retriever import retrieve_context
from llm.analyzer import analyze_finding

# Create DB schema
Base.metadata.create_all(bind=engine)

app = FastAPI(title="CodeShield API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For demo purposes allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target_dir: str
    git_token: Optional[str] = None

def perform_scan_task(target_dir: str, scan_id: str, git_token: Optional[str] = None):
    # Create a fresh database session for the background task
    db = next(get_db())
    
    is_git = target_dir.startswith("http://") or target_dir.startswith("https://") or target_dir.endswith(".git")
    temp_dir_obj = None
    scan_target = target_dir

    try:
        if is_git:
            temp_dir_obj = tempfile.TemporaryDirectory()
            scan_target = temp_dir_obj.name
            
            clone_url = target_dir
            if git_token and clone_url.startswith("https://"):
                parsed = urllib.parse.urlparse(clone_url)
                clone_url = parsed._replace(netloc=f"{git_token}@{parsed.netloc}").geturl()

            subprocess.run(["git", "-c", "http.version=HTTP/1.1", "-c", "http.postBuffer=524288000", "clone", clone_url, scan_target], check=True)

        # 1. Detection (Semgrep)
        raw_findings = run_semgrep(scan_target)
        
        # 2. Reachability & Risk Scoring
        findings_with_risk = enhance_findings_with_risk(raw_findings, scan_target)
        
        # 3. LLM Investigation Pipeline
        def process_finding(finding):
            risk_score = finding.get('risk_score', 0)
            if risk_score < 40:
                # Skip LLM for low risk
                return {
                    "finding": finding,
                    "explanation": "Skipped LLM analysis due to low risk score.",
                    "confidence": "N/A",
                    "fix": "N/A"
                }
            
            # Retrieve context based on rule ID or message
            query = f"{finding['id']} {finding.get('message', '')}"
            rag_context = retrieve_context(query)
            
            # Analyze using local LLM
            llm_result = analyze_finding(finding, rag_context)
            
            return {
                "finding": finding,
                "explanation": llm_result.get('explanation'),
                "confidence": llm_result.get('confidence'),
                "fix": llm_result.get('fix'),
                "patch_target": llm_result.get('patch_target'),
                "patch_replacement": llm_result.get('patch_replacement')
            }

        # Process all findings in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(process_finding, findings_with_risk))

        # Save findings to DB
        for res in results:
            finding = res["finding"]
            db_finding = models.Finding(
                scan_id=scan_id,
                rule_id=finding['id'],
                file_path=finding['file'],
                line_number=finding['line'],
                severity=finding['severity'],
                risk_score=finding.get('risk_score', 0),
                explanation=res['explanation'],
                confidence=res['confidence'],
                fix_recommendation=res['fix'],
                patch_target=res.get('patch_target'),
                patch_replacement=res.get('patch_replacement')
            )
            db.add(db_finding)
        
        # Update scan status
        scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
        if scan:
            scan.status = "completed"
        db.commit()
            
    except Exception as e:
        print(f"Error during scan: {e}")
        scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()
    finally:
        db.close()
        if temp_dir_obj:
            temp_dir_obj.cleanup()

@app.post("/scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = request.target_dir
    is_git = target.startswith("http://") or target.startswith("https://") or target.endswith(".git")

    if not is_git and not os.path.exists(target):
        raise HTTPException(status_code=400, detail="Target directory does not exist locally.")
        
    new_scan = models.ScanHistory(target_dir=target, status="running")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    background_tasks.add_task(perform_scan_task, request.target_dir, new_scan.id, request.git_token)
    
    return {"message": "Scan started", "scan_id": new_scan.id}

@app.get("/scan/{scan_id}")
def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return {
        "scan_id": scan.id,
        "target_dir": scan.target_dir,
        "status": scan.status,
        "timestamp": scan.timestamp,
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "explanation": f.explanation,
                "confidence": f.confidence,
                "fix_recommendation": f.fix_recommendation,
                "patch_target": f.patch_target,
                "patch_replacement": f.patch_replacement
            } for f in scan.findings
        ]
    }

@app.get("/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(models.ScanHistory).order_by(models.ScanHistory.timestamp.desc()).all()
    return [{"id": s.id, "target_dir": s.target_dir, "timestamp": s.timestamp, "status": s.status} for s in scans]

@app.delete("/history")
def clear_all_history(db: Session = Depends(get_db)):
    db.query(models.ScanHistory).delete()
    db.commit()
    return {"message": "All scan history cleared"}

@app.delete("/history/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}

@app.post("/apply_fix/{finding_id}")
def apply_fix(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.patch_target or not finding.patch_replacement:
        raise HTTPException(status_code=400, detail="No automated patch available for this finding")
    if not os.path.exists(finding.file_path):
        raise HTTPException(status_code=404, detail="Target file no longer exists on disk")

    try:
        with open(finding.file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if finding.patch_target not in content:
            raise HTTPException(status_code=400, detail="Target code snippet not found in file (file may have been modified)")

        new_content = content.replace(finding.patch_target, finding.patch_replacement)

        with open(finding.file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return {"message": "Fix applied successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

