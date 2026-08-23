from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
import os
import sys
import concurrent.futures

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

def perform_scan_task(target_dir: str, scan_id: str):
    # Create a fresh database session for the background task
    db = next(get_db())
    try:
        # 1. Detection (Semgrep)
        raw_findings = run_semgrep(target_dir)
        
        # 2. Reachability & Risk Scoring
        findings_with_risk = enhance_findings_with_risk(raw_findings, target_dir)
        
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
                "fix": llm_result.get('fix')
            }

        # Process all findings in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
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
                fix_recommendation=res['fix']
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

@app.post("/scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not os.path.exists(request.target_dir):
        raise HTTPException(status_code=400, detail="Target directory does not exist locally.")
        
    new_scan = models.ScanHistory(target_dir=request.target_dir, status="running")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    background_tasks.add_task(perform_scan_task, request.target_dir, new_scan.id)
    
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
                "fix_recommendation": f.fix_recommendation
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
