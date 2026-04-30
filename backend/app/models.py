from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON
from sqlalchemy.sql import func
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(8), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    total_lines = Column(Integer)
    risk_score = Column(Float, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    scan_results = Column(JSON)
    analysis_type = Column(String(50), default="basic")
    created_at = Column(DateTime, server_default=func.now())

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(8), index=True, nullable=False)
    rule = Column(String(255))
    severity = Column(String(20))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    message = Column(Text)
    fix = Column(Text)
    matched_cve_id = Column(String(50))
    matched_cve_title = Column(String(255))
    similarity_score = Column(Float)
    ai_explanation = Column(Text)
    created_at = Column(DateTime, server_default=func.now())