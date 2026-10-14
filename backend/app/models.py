from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    role = Column(String(40), nullable=False, default="researcher", index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    actor_email = Column(String(255), nullable=False, default="system")
    action = Column(String(120), nullable=False, index=True)
    target = Column(String(255), nullable=True)
    details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(512), nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    md5 = Column(String(32), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_type = Column(String(120), default="unknown")
    verdict = Column(String(40), default="needs_review", index=True)
    severity = Column(String(24), default="low", index=True)
    risk_score = Column(Float, default=0)
    ml_label = Column(String(40), nullable=True)
    ml_score = Column(Float, nullable=True)
    yara_count = Column(Integer, default=0)
    result_json = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="open", index=True)
    severity = Column(String(24), nullable=False, default="medium")
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class ResearchAnnotation(Base):
    __tablename__ = "research_annotations"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False, index=True)
    ground_truth = Column(String(24), nullable=False, default="unknown")
    family = Column(String(120), nullable=True)
    dataset_source = Column(String(255), nullable=False, default="local scan")
    notes = Column(Text, nullable=False, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class ExperimentNote(Base):
    __tablename__ = "experiment_notes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    tags = Column(String(500), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
