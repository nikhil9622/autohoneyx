
# 🔐 AutoHoneyX Security Enhancements & Cloud Deployment Guide

---

## **PART 1: SECURITY HARDENING** 🛡️

### **A. Application-Level Security**

#### **1. Input Validation & Sanitization**
```python
# app/security/validators.py
from pydantic import BaseModel, validator, EmailStr
from typing import Optional
import re

class TokenInjectionRequest(BaseModel):
    repo_path: str
    token_types: list[str]
    files_per_type: int = 5
    
    @validator('repo_path')
    def validate_repo_path(cls, v):
        # Prevent path traversal attacks
        if '..' in v or v.startswith('/'):
            raise ValueError('Invalid repository path')
        # Whitelist allowed characters
        if not re.match(r'^[a-zA-Z0-9/_.-]+$', v):
            raise ValueError('Repository path contains invalid characters')
        return v
    
    @validator('files_per_type')
    def validate_files_per_type(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Files per type must be between 1 and 100')
        return v

class AlertConfigRequest(BaseModel):
    slack_webhook: Optional[str] = None
    email_recipients: list[EmailStr] = []
    
    @validator('slack_webhook')
    def validate_slack_webhook(cls, v):
        if v and not v.startswith('https://hooks.slack.com/'):
            raise ValueError('Invalid Slack webhook URL')
        return v
```

#### **2. Rate Limiting & Throttling**
```python
# app/security/rate_limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, HTTPException
from functools import wraps

limiter = Limiter(key_func=get_remote_address)

# In realtime_api.py
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/tokens/generate")
@limiter.limit("10/minute")  # 10 requests per minute
async def generate_token(request: TokenRequest):
    # Generate token logic
    pass

@app.post("/api/inject")
@limiter.limit("5/minute")   # 5 injections per minute
async def inject_tokens(request: TokenInjectionRequest):
    # Injection logic
    pass

# Custom per-user limiting
@app.post("/api/scan")
@limiter.limit("20/hour")    # 20 scans per hour
async def scan_repository(request: ScanRequest, user_id: str = Depends(get_current_user)):
    # Scan logic
    pass
```

#### **3. Authentication & Authorization (OAuth2 + JWT)**
```python
# app/security/auth.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredential
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import os

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthCredential = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user_id

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

async def get_current_admin_user(user_id: str = Depends(get_current_user)):
    # Check user role from database
    with get_db_session() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or user.role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Not authorized")
    return user_id
```

#### **4. Encryption at Rest & in Transit**
```python
# app/security/encryption.py
from cryptography.fernet import Fernet
from sqlalchemy.types import TypeDecorator, String
import os

ENCRYPTION_KEY = os.getenv("ENCRYPTION_MASTER_KEY")
cipher_suite = Fernet(ENCRYPTION_KEY)

class EncryptedString(TypeDecorator):
    """SQLAlchemy type for encrypted database fields"""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return cipher_suite.encrypt(value.encode()).decode()
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return cipher_suite.decrypt(value.encode()).decode()
        return value

# Usage in models
class Honeytoken(Base):
    __tablename__ = "honeytokens"
    
    id = Column(String(36), primary_key=True)
    token_id = Column(String(255), unique=True)
    token_value = Column(EncryptedString(500))  # Encrypted!
    api_key = Column(EncryptedString(255))      # Encrypted!
```

#### **5. SQL Injection Prevention** (Already using SQLAlchemy ORM)
```python
# Ensure parameterized queries everywhere
# ✅ GOOD - Using ORM
users = db.query(User).filter(User.email == user_email).all()

# ✅ GOOD - Using text() with parameters
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE email = :email"), 
                   {"email": user_email})

# ❌ BAD - String concatenation (NEVER DO THIS)
# result = db.execute(f"SELECT * FROM users WHERE email = '{user_email}'")
```

#### **6. CORS & Security Headers**
```python
# app/realtime_api.py
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:8501").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    max_age=3600,
)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

### **B. Database Security**

#### **1. Row-Level Security (PostgreSQL)**
```sql
-- Enable RLS on sensitive tables
ALTER TABLE honeytokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

-- Create policy: Users see only their org's data
CREATE POLICY organization_isolation ON honeytokens
    FOR SELECT
    USING (organization_id = current_setting('user.org_id')::uuid);

-- Create policy: Admins can see everything
CREATE POLICY admin_access ON honeytokens
    FOR ALL
    USING (current_user_role() = 'admin');
```

#### **2. Database Audit Logging**
```python
# app/database_audit.py
from sqlalchemy.orm import Session
from sqlalchemy import event
from app.models import AuditLog
from datetime import datetime

@event.listens_for(Honeytoken, 'after_insert')
def receive_after_insert(mapper, connection, target):
    audit = AuditLog(
        action='INSERT',
        table_name='honeytokels',
        record_id=target.id,
        changes={'created': target.token_id},
        timestamp=datetime.utcnow()
    )
    connection.execute(audit.__table__.insert().values(**audit.__dict__))

@event.listens_for(Honeytoken, 'after_update')
def receive_after_update(mapper, connection, target):
    audit = AuditLog(
        action='UPDATE',
        table_name='honeytokens',
        record_id=target.id,
        changes=target.get_modified_fields(),
        timestamp=datetime.utcnow()
    )
    connection.execute(audit.__table__.insert().values(**audit.__dict__))
```

#### **3. Connection Pooling & Secrets Management**
```python
# app/database.py
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
import os

# Use AWS Secrets Manager for credentials
try:
    from aws_secretsmanager_caching import SecretCache
    cache = SecretCache()
    db_password = cache.get_secret_string("autohoneyx/db-password")
except:
    db_password = os.getenv("DB_PASSWORD")

DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{db_password}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
    echo=False,
    # SSL Connection
    connect_args={
        "sslmode": "require",
        "sslcert": "/etc/ssl/certs/ca.crt"
    }
)
```

---

### **C. Network & Infrastructure Security**

#### **1. API Security & DDoS Protection**
```python
# Use AWS WAF + CloudFront in front of API
# In docker-compose or k8s, add rate limiting via nginx

# nginx.conf
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=dashboard_limit:10m rate=30r/s;

server {
    listen 80;
    
    # API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://autohoneyx_api;
    }
    
    # Dashboard
    location / {
        limit_req zone=dashboard_limit burst=50 nodelay;
        proxy_pass http://autohoneyx_dashboard;
    }
    
    # Enable SSL/TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
}
```

#### **2. Firewall Rules (Terraform)**
```hcl
# Security groups for cloud deployment

resource "aws_security_group" "autohoneyx_api" {
  name = "autohoneyx-api-sg"
  
  # Allow HTTPS from CloudFront only
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # VPC CIDR
  }
  
  # Allow PostgreSQL from app tier only
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.autohoneyx_db.id]
  }
  
  # Deny all inbound by default
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

#### **3. Secrets Management**
```python
# app/secrets/aws_secrets.py
import boto3
import json

client = boto3.client('secretsmanager')

def get_secret(secret_name):
    try:
        response = client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            return json.loads(response['SecretString'])
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None

# Usage
db_credentials = get_secret('autohoneyx/database')
slack_webhook = get_secret('autohoneyx/slack-webhook')
github_token = get_secret('autohoneyx/github-token')
```

---

## **PART 2: ADVANCED CYBERSECURITY FEATURES** 🎯

### **A. Threat Intelligence Integration**

#### **1. IP Reputation Checking**
```python
# app/threat_intel/ip_reputation.py
import requests
import os

class ThreatIntelligence:
    def __init__(self):
        self.abuseipdb_api = os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_api = os.getenv("VIRUSTOTAL_API_KEY")
    
    def check_ip_reputation(self, ip_address):
        """Check IP against multiple threat intel sources"""
        
        # AbuseIPDB
        abuseipdb_score = self._check_abuseipdb(ip_address)
        
        # VirusTotal
        vt_detections = self._check_virustotal(ip_address)
        
        # Geolocation + VPN/Proxy detection
        geo_data = self._get_geolocation(ip_address)
        
        return {
            'ip': ip_address,
            'abuseipdb_score': abuseipdb_score,
            'virustotal_detections': vt_detections,
            'geolocation': geo_data,
            'is_malicious': abuseipdb_score > 75 or (vt_detections and vt_detections['malicious'] > 5),
            'is_vpn_proxy': geo_data.get('is_vpn', False)
        }
    
    def _check_abuseipdb(self, ip_address):
        """Query AbuseIPDB for malicious IP reputation"""
        headers = {
            'Key': self.abuseipdb_api,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params
        )
        return response.json()['data']['abuseConfidenceScore']
    
    def _check_virustotal(self, ip_address):
        """Query VirusTotal for IP reputation"""
        headers = {
            'x-apikey': self.virustotal_api
        }
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
            headers=headers
        )
        if response.status_code == 200:
            last_analysis = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': last_analysis['malicious'],
                'suspicious': last_analysis['suspicious'],
                'detections': last_analysis['malicious'] + last_analysis['suspicious']
            }
        return None

# Usage in monitoring
@app.post("/api/attack-logs/analyze")
async def analyze_attack(log_id: str):
    attack_log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
    threat_intel = ThreatIntelligence()
    reputation = threat_intel.check_ip_reputation(attack_log.source_ip)
    
    if reputation['is_malicious']:
        # Create CRITICAL alert
        alert = Alert(
            title=f"Malicious IP Attack: {reputation['ip']}",
            severity="CRITICAL",
            message=f"AbuseIPDB Score: {reputation['abuseipdb_score']}, VirusTotal: {reputation['virustotal_detections']}",
            alert_type="THREAT_INTEL_MATCH"
        )
        db.add(alert)
        db.commit()
```

#### **2. YARA Rules for Malware Detection**
```python
# app/threat_intel/yara_scanner.py
import yara
import os

class YaraScanner:
    def __init__(self):
        # Load YARA rules
        self.rules = yara.compile(
            filepaths={
                'malware': 'rules/malware.yar',
                'webshell': 'rules/webshell.yar',
                'credentials': 'rules/credentials.yar'
            }
        )
    
    def scan_attack_data(self, attack_data):
        """Scan attack payloads against YARA rules"""
        matches = self.rules.match(data=attack_data)
        
        detections = []
        for match in matches:
            detections.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'strings_found': len(match.strings)
            })
        
        return detections if detections else None
```

**YARA Rules Example (rules/webshell.yar):**
```yara
rule WebShell_PHP {
    strings:
        $php = "<?php" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $passthru = "passthru(" nocase
    condition:
        $php and any of ($exec, $system, $passthru)
}

rule WebShell_ASP {
    strings:
        $asp = "<%"
        $eval = "eval(" nocase
        $shell = "Shell.CreateObject" nocase
    condition:
        $asp and any of ($eval, $shell)
}
```

### **B. MITRE ATT&CK Framework Integration**

```python
# app/threat_intel/mitre_attack.py
import requests

class MitreAttackMapper:
    def __init__(self):
        self.mitre_api = "https://attack.mitre.org/api/v2"
        self.technique_mappings = {
            'brute_force': ['T1110'],
            'credential_access': ['T1110', 'T1187', 'T1056'],
            'reconnaissance': ['T1592', 'T1589', 'T1590'],
            'lateral_movement': ['T1021', 'T1091'],
            'exfiltration': ['T1020', 'T1030', 'T1048'],
            'defense_evasion': ['T1548', 'T1197', 'T1036']
        }
    
    def get_attack_tactics(self, attack_category):
        """Map detected attack to MITRE ATT&CK techniques"""
        techniques = self.technique_mappings.get(attack_category, [])
        
        details = []
        for technique_id in techniques:
            details.append({
                'id': technique_id,
                'url': f'https://attack.mitre.org/techniques/{technique_id}',
                'severity': self._get_technique_severity(technique_id)
            })
        
        return details
    
    def _get_technique_severity(self, technique_id):
        # In production, call MITRE API
        severity_map = {
            'T1110': 'HIGH',
            'T1187': 'MEDIUM',
            'T1592': 'LOW'
        }
        return severity_map.get(technique_id, 'MEDIUM')
```

### **C. Deception Detection**

```python
# app/deception/honeypot_evasion_detection.py
import re

class HoneypotEvasionDetector:
    def __init__(self):
        # Common evasion techniques
        self.evasion_patterns = {
            'timeout_detection': {
                'patterns': [
                    r'timeout|sleep|\bwait\b|delay',
                    r'ping.*127\.0\.0\.1|localhost'
                ],
                'score': 0.6
            },
            'fingerprint_detection': {
                'patterns': [
                    r'honeypot|honeyclient|decoy',
                    r'suricata|snort|bro|zeek|cowrie',
                    r'docker|vm|virtualbox|vmware'
                ],
                'score': 0.8
            },
            'evasion_commands': {
                'patterns': [
                    r'whoami|uname -a|python -c.*socket',
                    r'nc -zv|telnet.*22',
                    r'nmap -sV|masscan'
                ],
                'score': 0.7
            }
        }
    
    def detect_evasion_attempts(self, user_input, user_agent, source_ip):
        """Detect if attacker is trying to evade honeypot"""
        
        evasion_score = 0
        detected_techniques = []
        
        for technique, config in self.evasion_patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, str(user_input).lower()):
                    evasion_score += config['score']
                    detected_techniques.append(technique)
        
        return {
            'is_evasion_attempt': evasion_score > 0.5,
            'evasion_score': min(evasion_score, 1.0),
            'techniques_detected': list(set(detected_techniques))
        }
```

### **D. Advanced Behavioral Analysis**

```python
# app/ml/advanced_analytics.py
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

class AdvancedBehavioralAnalytics:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.05)
    
    def detect_anomalous_patterns(self, attack_logs):
        """Use unsupervised ML to find anomalous attack patterns"""
        
        df = pd.DataFrame([
            {
                'hour_of_day': log.timestamp.hour,
                'request_size': len(log.request_body or ''),
                'response_time': log.response_time if hasattr(log, 'response_time') else 0,
                'unique_source_ips': 1,
                'failed_attempts_in_2h': self._count_failed_attempts(log.source_ip)
            }
            for log in attack_logs
        ])
        
        predictions = self.isolation_forest.fit_predict(df)
        
        anomalies = []
        for idx, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                anomalies.append({
                    'log_id': attack_logs[idx].id,
                    'anomaly_score': self.isolation_forest.score_samples(df.iloc[[idx]])[0],
                    'reason': self._explain_anomaly(df.iloc[idx])
                })
        
        return anomalies
    
    def _explain_anomaly(self, row):
        """Explain why this pattern is anomalous"""
        reasons = []
        
        if row['hour_of_day'] < 2 or row['hour_of_day'] > 22:
            reasons.append("Attack at unusual hour")
        
        if row['request_size'] > 10000:
            reasons.append("Unusually large payload")
        
        if row['failed_attempts_in_2h'] > 20:
            reasons.append("High failed attempt frequency")
        
        return "; ".join(reasons) if reasons else "Unknown anomaly"
```

---

## **PART 3: CLOUD DEPLOYMENT ARCHITECTURE** ☁️

### **A. AWS Deployment (Recommended for Production)**

#### **1. Complete AWS Architecture (Terraform IaC)**
```hcl
# infrastructure/main.tf

# VPC Setup
resource "aws_vpc" "autohoneyx" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "autohoneyx-vpc"
  }
}

# Public Subnets (ALB, NAT Gateway)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.autohoneyx.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
}

# Private Subnets (ECS, RDS)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.autohoneyx.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
}

# RDS PostgreSQL (Multi-AZ for HA)
resource "aws_rds_cluster" "autohoneyx" {
  cluster_identifier      = "autohoneyx-db"
  engine                  = "aurora-postgresql"
  engine_version          = "14.6"
  database_name           = "autohoneyx_db"
  master_username         = "autohoneyx"
  master_password         = random_password.db_password.result
  db_subnet_group_name    = aws_db_subnet_group.autohoneyx.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  backup_retention_period = 30
  preferred_backup_window = "03:00-04:00"
  skip_final_snapshot     = false
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  tags = {
    Name = "autohoneyx-db"
  }
}

# ECS Cluster (Containerized Services)
resource "aws_ecs_cluster" "autohoneyx" {
  name = "autohoneyx-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ALB (Application Load Balancer)
resource "aws_lb" "autohoneyx" {
  name               = "autohoneyx-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  
  enable_deletion_protection = false
}

# ALB Target Groups
resource "aws_lb_target_group" "api" {
  name        = "autohoneyx-api"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.autohoneyx.id
  target_type = "ip"
  
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }
}

resource "aws_lb_target_group" "dashboard" {
  name        = "autohoneyx-dashboard"
  port        = 8501
  protocol    = "HTTP"
  vpc_id      = aws_vpc.autohoneyx.id
  target_type = "ip"
}

# ECS Task Definition - API
resource "aws_ecs_task_definition" "api" {
  family                   = "autohoneyx-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  
  container_definitions = jsonencode([
    {
      name      = "autohoneyx-api"
      image     = "${aws_ecr_repository.autohoneyx.repository_url}:latest"
      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "DATABASE_URL"
          value = "postgresql://${aws_rds_cluster.autohoneyx.master_username}:${random_password.db_password.result}@${aws_rds_cluster.autohoneyx.endpoint}:5432/autohoneyx_db"
        },
        {
          name  = "ENVIRONMENT"
          value = "production"
        }
      ]
      secrets = [
        {
          name      = "SLACK_WEBHOOK_URL"
          valueFrom = "${aws_secretsmanager_secret.slack_webhook.arn}:SLACK_WEBHOOK_URL::"
        },
        {
          name      = "GITHUB_TOKEN"
          valueFrom = "${aws_secretsmanager_secret.github_token.arn}:GITHUB_TOKEN::"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "api"
        }
      }
    }
  ])
}

# ECS Service - API
resource "aws_ecs_service" "api" {
  name            = "autohoneyx-api-service"
  cluster         = aws_ecs_cluster.autohoneyx.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  
  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "autohoneyx-api"
    container_port   = 8000
  }

  # Auto-scaling
  depends_on = [
    aws_lb_listener.http_api,
    aws_iam_role_policy.ecs_task_execution_role_policy
  ]
}

# Auto Scaling Group for ECS
resource "aws_autoscaling_target" "ecs_target" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.autohoneyx.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_autoscaling_policy" "ecs_policy_cpu" {
  name               = "cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_autoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_autoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_autoscaling_target.ecs_target.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# CloudFront (CDN + WAF)
resource "aws_cloudfront_distribution" "autohoneyx" {
  enabled = true
  
  origin {
    domain_name = aws_lb.autohoneyx.dns_name
    origin_id   = "alb"
    
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "alb"
    
    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Host"]
      cookies {
        forward = "all"
      }
    }
    
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
    # Or use AWS Certificate Manager:
    # acm_certificate_arn = aws_acm_certificate.autohoneyx.arn
    # ssl_support_method  = "sni-only"
  }
  
  web_acl_id = aws_wafv2_web_acl.autohoneyx.arn
}

# WAF (Web Application Firewall)
resource "aws_wafv2_web_acl" "autohoneyx" {
  name  = "autohoneyx-waf"
  scope = "CLOUDFRONT"
  
  default_action {
    allow {}
  }
  
  rule {
    name     = "RateLimiting"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitingMetric"
      sampled_requests_enabled   = true
    }
  }
  
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
}

# GuardDuty (Threat Detection)
resource "aws_guardduty_detector" "autohoneyx" {
  enable = true
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "api_high_latency" {
  alarm_name          = "autohoneyx-api-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1000
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "autohoneyx-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
```

#### **2. AWS Services Mapping**

| Component | AWS Service | Purpose |
|-----------|-------------|---------|
| **Containers** | ECS Fargate / EKS | Run API, Dashboard, Monitoring |
| **Database** | Aurora PostgreSQL (RDS) | High availability, auto-scaling |
| **Secrets** | AWS Secrets Manager | Store API keys, tokens securely |
| **File Storage** | S3 | Store logs, malware samples, reports |
| **Message Queue** | SQS | Async alert queue, long-running jobs |
| **Background Jobs** | Lambda / SQS | Event-driven processing |
| **CDN** | CloudFront | Distribute dashboard globally |
| **DDoS/WAF** | AWS WAF + Shield | Protect against attacks |
| **Threat Detection** | GuardDuty | Detect intrusions in AWS |
| **Monitoring** | CloudWatch | Logs, metrics, alarms |
| **SIEM Integration** | Security Hub | Centralized security findings |
| **DNS** | Route 53 | Domain management, failover |
| **SSL/TLS** | ACM | Free SSL certificates |
| **Code Scanning** | CodeBuild + Snyk | CI/CD security scanning |

#### **3. AWS Lambda for Serverless Analysis**
```python
# lambda/honeypot_analyzer.py
import json
import boto3
import asyncio
from app.threat_intel.ip_reputation import ThreatIntelligence
from app.threat_intel.yara_scanner import YaraScanner

s3_client = boto3.client('s3')
rds_client = boto3.client('rds')

def lambda_handler(event, context):
    """
    Triggered when attack log is written to S3
    Performs async analysis without blocking main service
    """
    
    # Extract attack data from event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Download attack payload
    response = s3_client.get_object(Bucket=bucket, Key=key)
    attack_data = response['Body'].read()
    
    # Threat intelligence
    threat_intel = ThreatIntelligence()
    ip_reputation = threat_intel.check_ip_reputation(attack_data.get('source_ip'))
    
    # YARA scanning
    yara_scanner = YaraScanner()
    yara_matches = yara_scanner.scan_attack_data(attack_data.get('payload'))
    
    # Save results to RDS
    save_analysis_results(
        attack_id=attack_data['id'],
        ip_reputation=ip_reputation,
        yara_matches=yara_matches
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps('Analysis complete')
    }
```

---

### **B. Kubernetes Deployment (EKS / AKS / GKE)**

#### **Helm Chart for AutoHoneyX**
```yaml
# helm/autohoneyx/Chart.yaml
apiVersion: v2
name: autohoneyx
description: A Helm chart for AutoHoneyX security platform
type: application
version: 1.0.0
appVersion: "1.0.0"

---
# helm/autohoneyx/values.yaml
replicaCount: 3

image:
  repository: autohoneyx/app
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 8000
  targetPort: 8000

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

postgres:
  enabled: true
  auth:
    username: autohoneyx
    password: change-me
    database: autohoneyx_db

ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: autohoneyx.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: autohoneyx-tls
      hosts:
        - autohoneyx.example.com

---
# helm/autohoneyx/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "autohoneyx.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: autohoneyx
  template:
    metadata:
      labels:
        app: autohoneyx
    spec:
      containers:
      - name: autohoneyx
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: autohoneyx-secrets
              key: database-url
        - name: SLACK_WEBHOOK_URL
          valueFrom:
            secretKeyRef:
              name: autohoneyx-secrets
              key: slack-webhook
        resources:
          {{- toYaml .Values.resources | nindent 12 }}
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

#### **Network Policy (Kubernetes)**
```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: autohoneyx-netpol
spec:
  podSelector:
    matchLabels:
      app: autohoneyx
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - protocol: TCP
      port: 8000
  - from:
    - podSelector:
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 53  # DNS
    - protocol: UDP
      port: 53
  # Allow external HTTPS for threat intel APIs
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

---

### **C. Multi-Cloud Deployment**

#### **Azure Deployment (ARM Template)**
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2021-09-01",
      "name": "autohoneyx-aci",
      "location": "[resourceGroup().location]",
      "properties": {
        "containers": [
          {
            "name": "autohoneyx-api",
            "properties": {
              "image": "autohoneyx/app:latest",
              "resources": {
                "requests": {
                  "cpu": 1.0,
                  "memoryInGb": 1.0
                }
              },
              "ports": [
                {
                  "port": 8000,
                  "protocol": "TCP"
                }
              ],
              "environmentVariables": [
                {
                  "name": "DATABASE_URL",
                  "secureValue": "[parameters('databaseUrl')]"
                }
              ]
            }
          }
        ],
        "osType": "Linux",
        "ipAddress": {
          "type": "Public",
          "ports": [
            {
              "port": 8000,
              "protocol": "TCP"
            }
          ]
        },
        "imageRegistryCredentials": [
          {
            "server": "[parameters('registryLoginServer')]",
            "username": "[parameters('registryUsername')]",
            "password": "[parameters('registryPassword')]"
          }
        ]
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers",
      "apiVersion": "2017-12-01",
      "name": "autohoneyx-db",
      "location": "[resourceGroup().location]",
      "properties": {
        "createMode": "Default",
        "administratorLogin": "autohoneyx",
        "administratorLoginPassword": "[parameters('dbPassword')]",
        "version": "12",
        "storageMB": 51200,
        "backupRetentionDays": 30,
        "geoRedundantBackup": "Enabled"
      }
    }
  ]
}
```

#### **Google Cloud Deployment (Cloud Run)**
```yaml
# gcp/cloud-run-config.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: autohoneyx-api
  namespace: default
spec:
  template:
    spec:
      containers:
      - image: gcr.io/my-project/autohoneyx:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: autohoneyx-secrets
              key: database-url
        - name: PORT
          value: "8000"
        resources:
          limits:
            memory: "1Gi"
            cpu: "1"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
      timeoutSeconds: 300
      serviceAccountName: autohoneyx-sa
  traffic:
  - percent: 100
    latestRevision: true
```

---

### **D. CI/CD Pipeline (GitHub Actions + Cloud Deployment)**

```yaml
# .github/workflows/deploy.yml
name: Deploy to AWS

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: autohoneyx

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SAST (Semgrep)
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
      
      - name: Run Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'AutoHoneyX'
          path: '.'
          format: 'JSON'
      
      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@master
        env:
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost/test_db
        run: pytest --cov=app tests/

  build-and-push:
    needs: [security-scan, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      
      - name: Build and push Docker image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          docker tag $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG $ECR_REGISTRY/$ECR_REPOSITORY:latest
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to ECS
        env:
          CLUSTER_NAME: autohoneyx-cluster
          SERVICE_NAME: autohoneyx-api-service
          TASK_DEFINITION: autohoneyx-api
        run: |
          aws ecs update-service \
            --cluster $CLUSTER_NAME \
            --service $SERVICE_NAME \
            --force-new-deployment
```

---

## **SUMMARY: Security Enhancements & Cloud Components**

| Enhancement | Priority | Effort | Impact |
|-------------|----------|--------|--------|
| **Input Validation** | CRITICAL | Low | HIGH |
| **Rate Limiting** | CRITICAL | Low | HIGH |
| **JWT Auth** | CRITICAL | Medium | HIGH |
| **Encryption at Rest** | CRITICAL | Medium | HIGH |
| **Database Audit Logging** | HIGH | Medium | MEDIUM |
| **Threat Intelligence API** | HIGH | High | VERY HIGH |
| **YARA Rules** | MEDIUM | High | HIGH |
| **MITRE ATT&CK Mapping** | MEDIUM | Medium | MEDIUM |
| **Honeypot Evasion Detection** | MEDIUM | Medium | MEDIUM |
| **AWS Deployment** | CRITICAL | Very High | CRITICAL |
| **Kubernetes** | HIGH | Very High | HIGH |
| **CI/CD Security** | HIGH | Medium | HIGH |

---

**Recommended Implementation Roadmap:**
1. **Week 1-2**: Input validation + JWT auth + Rate limiting
2. **Week 3**: Encryption + DB audit logging  
3. **Week 4**: Threat intelligence integration
4. **Week 5-6**: YARA rules + Behavioral analysis
5. **Week 7-8**: AWS deployment (Terraform IaC)
6. **Week 9**: Kubernetes migration
7. **Week 10**: CI/CD security + monitoring

This will transform AutoHoneyX into an **enterprise-grade, production-ready security platform**! 🚀
