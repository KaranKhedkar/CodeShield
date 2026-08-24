from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from .session import Base
from datetime import datetime
import uuid

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_dir = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="completed")
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scan_history.id"))
    rule_id = Column(String, index=True)
    file_path = Column(String)
    line_number = Column(Integer)
    severity = Column(String)
    risk_score = Column(Float)
    
    # LLM Investigation data
    explanation = Column(String, nullable=True)
    confidence = Column(String, nullable=True)
    fix_recommendation = Column(String, nullable=True)
    patch_target = Column(String, nullable=True)
    patch_replacement = Column(String, nullable=True)

    scan = relationship("ScanHistory", back_populates="findings")
