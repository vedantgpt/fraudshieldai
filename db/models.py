"""FraudShield AI database models."""
from sqlalchemy import create_engine, Column, String, Integer, Float, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from config import DATABASE_URL

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class APK(Base):
    __tablename__ = "apks"
    id = Column(String, primary_key=True)
    file_name = Column(String)
    package_name = Column(String)
    sha256 = Column(String, unique=True)
    file_size = Column(Integer)
    version_name = Column(String)
    version_code = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(JSON)


class StaticFinding(Base):
    __tablename__ = "static_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    finding_id = Column(String)
    title = Column(String)
    severity = Column(String)
    file_path = Column(String)
    line = Column(Integer)
    evidence = Column(Text)


class DynamicFinding(Base):
    __tablename__ = "dynamic_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    finding_type = Column(String)
    severity = Column(String)
    description = Column(Text)
    evidence = Column(Text)
    sandbox = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class IOC(Base):
    __tablename__ = "ioc"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    ioc_type = Column(String)
    value = Column(String)


class MITREMapping(Base):
    __tablename__ = "mitre_mapping"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    technique_id = Column(String)
    technique = Column(String)
    tactic = Column(String)
    evidence = Column(Text)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    score = Column(Integer)
    category = Column(String)
    static_score = Column(Integer)
    dynamic_score = Column(Integer)
    fraud_score = Column(Integer)
    ai_confidence = Column(Float)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    apk_id = Column(String)
    report_type = Column(String)
    file_path = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id = Column(String, primary_key=True)
    apk_id = Column(String)
    messages = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
