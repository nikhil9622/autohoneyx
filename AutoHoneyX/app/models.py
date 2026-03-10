"""Database models for AutoHoneyX"""

from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime, ForeignKey, DECIMAL, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

# Import database URL to check if we're using PostgreSQL or SQLite
from app.config import config

class Honeytoken(Base):
    """Honeytoken model"""
    __tablename__ = "honeytokens"

    # Use string for SQLite, UUID for PostgreSQL
    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID, INET
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        triggered_by_ip = Column(INET)
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        triggered_by_ip = Column(String(45))  # IPv6 addresses are up to 45 chars

    token_id = Column(String(255), unique=True, nullable=False, index=True)
    token_type = Column(String(50), nullable=False, index=True)  # aws, db, api, etc.
    token_value = Column(Text, nullable=False)
    token_metadata = Column('metadata', JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    triggered_at = Column(DateTime)
    triggered_by_user_agent = Column(Text)
    is_triggered = Column(Boolean, default=False, index=True)
    location_file = Column(String(500))
    location_line = Column(Integer)
    created_by = Column(String(100))
    
    # Relationships
    attack_logs = relationship("AttackLog", back_populates="honeytoken")
    alerts = relationship("Alert", back_populates="honeytoken")
    
    def __repr__(self):
        return f"<Honeytoken {self.token_id} ({self.token_type})>"

class AttackLog(Base):
    """Attack log model"""
    __tablename__ = "attack_logs"

    # Use string for SQLite, UUID for PostgreSQL
    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID, INET
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        source_ip = Column(INET, nullable=False, index=True)
        honeytoken_id = Column(UUID(as_uuid=True), ForeignKey("honeytokens.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        source_ip = Column(String(45), nullable=False, index=True)  # IPv6 addresses are up to 45 chars
        honeytoken_id = Column(String(36), ForeignKey("honeytokens.id"))

    honeypot_type = Column(String(50), nullable=False, index=True)  # ssh, web, db
    user_agent = Column(Text)
    request_path = Column(Text)
    request_method = Column(String(10))
    request_body = Column(Text)
    response_code = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_metadata = Column('metadata', JSON)
    severity = Column(String(20), default="MEDIUM")
    classification = Column(String(50))
    
    # Relationships
    honeytoken = relationship("Honeytoken", back_populates="attack_logs")
    alerts = relationship("Alert", back_populates="attack_log")
    behavior_analysis = relationship("BehaviorAnalysis", back_populates="attack_log")
    
    def __repr__(self):
        return f"<AttackLog {self.honeypot_type} from {self.source_ip}>"

class Alert(Base):
    """Alert model"""
    __tablename__ = "alerts"

    # Use string for SQLite, UUID for PostgreSQL
    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID, INET
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        source_ip = Column(INET)
        honeytoken_id = Column(UUID(as_uuid=True), ForeignKey("honeytokens.id"))
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        source_ip = Column(String(45))  # IPv6 addresses are up to 45 chars
        honeytoken_id = Column(String(36), ForeignKey("honeytokens.id"))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    sent_at = Column(DateTime)
    sent_via = Column(String(50))  # email, slack
    is_sent = Column(Boolean, default=False)
    alert_metadata = Column('metadata', JSON)
    
    # Relationships
    honeytoken = relationship("Honeytoken", back_populates="alerts")
    attack_log = relationship("AttackLog", back_populates="alerts")
    
    def __repr__(self):
        return f"<Alert {self.alert_type} - {self.severity}>"

class BehaviorAnalysis(Base):
    """Behavioral analysis results"""
    __tablename__ = "behavior_analysis"

    # Use string for SQLite, UUID for PostgreSQL
    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    category = Column(String(50), nullable=False)  # reconnaissance, exploitation, lateral_movement
    confidence = Column(DECIMAL(5, 4))
    features = Column(JSON)
    predictions = Column(JSON)
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    attack_log = relationship("AttackLog", back_populates="behavior_analysis")
    
    def __repr__(self):
        return f"<BehaviorAnalysis {self.category} ({self.confidence})>"

class AnomalyDetection(Base):
    """Anomaly detection results"""
    __tablename__ = "anomaly_detection"

    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    anomaly_score = Column(DECIMAL(5, 4), nullable=False)  # 0-1, higher = more anomalous
    is_anomalous = Column(Boolean, default=False, index=True)
    algorithm = Column(String(50))  # isolation_forest, lof, etc.
    deviation_type = Column(String(100))  # time_based, behavior_based, etc.
    detected_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(Text)
    
    def __repr__(self):
        return f"<AnomalyDetection score={self.anomaly_score}>"

class KillChainEvent(Base):
    """Kill chain mapping for attacks"""
    __tablename__ = "kill_chain_events"

    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    mitre_tactic = Column(String(100), nullable=False, index=True)  # Reconnaissance, Exploitation, etc.
    mitre_technique = Column(String(255), nullable=False)
    kill_chain_phase = Column(String(50))  # early, mid, late
    severity_score = Column(DECIMAL(5, 4))  # 0-1
    mapped_at = Column(DateTime, default=datetime.utcnow)
    confidence = Column(DECIMAL(5, 4))
    
    def __repr__(self):
        return f"<KillChainEvent {self.mitre_tactic}>"

class ForensicArtifact(Base):
    """Forensic artifacts collected during incident"""
    __tablename__ = "forensic_artifacts"

    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    artifact_type = Column(String(50), nullable=False)  # process, file, network, registry
    artifact_data = Column(JSON, nullable=False)
    severity = Column(String(20))
    collected_at = Column(DateTime, default=datetime.utcnow)
    system_hostname = Column(String(255))
    
    def __repr__(self):
        return f"<ForensicArtifact {self.artifact_type}>"

class IncidentTimeline(Base):
    """Timeline of events for incident"""
    __tablename__ = "incident_timeline"

    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        attack_log_id = Column(UUID(as_uuid=True), ForeignKey("attack_logs.id"))
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        attack_log_id = Column(String(36), ForeignKey("attack_logs.id"))

    event_sequence = Column(Integer)
    event_type = Column(String(50))  # token_created, token_injected, token_accessed, etc.
    event_description = Column(Text)
    event_timestamp = Column(DateTime, nullable=False)
    related_artifacts = Column(JSON)
    
    def __repr__(self):
        return f"<IncidentTimeline {self.event_type} @{self.event_sequence}>"

class PlaybookExecution(Base):
    """Playbook execution records"""
    __tablename__ = "playbook_executions"

    if "postgresql" in config.DATABASE_URL:
        from sqlalchemy.dialects.postgresql import UUID
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    else:
        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    playbook_name = Column(String(255), nullable=False, index=True)
    scenario_name = Column(String(255))
    execution_status = Column(String(50))  # pending, running, succeeded, failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    results = Column(JSON)
    logs = Column(Text)
    
    def __repr__(self):
        return f"<PlaybookExecution {self.playbook_name}>"

