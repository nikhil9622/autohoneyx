# 🍯 AutoHoneyX Full Working - Demo Walkthrough

## **Overview: What is AutoHoneyX?**

AutoHoneyX is an **intelligent honeytoken and honeypot management system** that automatically:
1. **Generates fake credentials** (honeytokens) - AWS keys, DB passwords, API tokens, SSH keys
2. **Injects them into your codebase** - Strategically places fake secrets in code files
3. **Detects when they're used** - When attackers/intruders try to use the fake credentials
4. **Analyzes attacks intelligently** - Maps to MITRE ATT&CK, calculates severity, detects anomalies
5. **Responds automatically** - Blocks IPs, triggers alerts, creates incident reports
6. **Provides visibility** - Real-time dashboard showing all security events

---

## **Architecture: The Complete Flow**

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
├─────────────────────────────────────────────────────────────────┤
│  Streamlit Dashboard  │  REST API (FastAPI)  │  Event Bus        │
└──────────┬──────────────────┬────────────────────┬───────────────┘
           │                  │                    │
           ▼                  ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                  SECURITY ENGINES LAYER                          │
├─────────────────────────────────────────────────────────────────┤
│ Honeytoken     │ Injection   │ Evasion Detection │              │
│ Generator      │ Engine      │ (Anti-Sandbox)    │              │
│                │             │                    │              │
│ Anomaly        │ Kill Chain  │ Threat Intel       │ Auto-        │
│ Detection      │ Analyzer    │ (IP Reputation)    │ Response     │
└──────────┬──────────────────┬────────────────────┬───────────────┘
           │                  │                    │
           ▼                  ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE LAYER                               │
├─────────────────────────────────────────────────────────────────┤
│ Honeytokens  │ AttackLogs  │ Alerts  │ AnomalyDetection         │
│ Honeypots    │ KillChain   │ Blocks  │ BehaviorAnalysis         │
└─────────────────────────────────────────────────────────────────┘
```

---

## **Step-by-Step Demo Workflow**

### **PHASE 1: TOKEN GENERATION & INJECTION**

#### **Step 1.1: User Opens Dashboard**
```
User navigates to: http://localhost:8501
Dashboard loads from: dashboard/app.py
```

**What the dashboard shows:**
- Honeytoken management (create, view, track)
- Injection engine (select project, inject tokens)
- Attack logs (real-time incidents)
- Analytics & severity scores

#### **Step 1.2: Generate Honeytokens**
```python
# From: app/honeytoken_generator.py

HoneytokenGenerator.generate_aws_key()
# Returns:
{
    'token_id': 'a1b2c3d4',
    'token_type': 'aws',
    'access_key_id': 'AKIA4X5Y6Z7A8B9C0D1E',  # Fake AWS key
    'secret_access_key': 'aB1+cD2/eF3+gH4/iJ5+kL6/mN7+oPq8r',  # Fake AWS secret
    'token_value': 'AWS_ACCESS_KEY_ID=AKIA...\nAWS_SECRET_ACCESS_KEY=...',
    'metadata': {'region': 'us-east-1', 'service': 'aws'}
}
```

**Supported token types:**
- `aws` - AWS credentials (access key + secret key)
- `db_postgresql`, `db_mysql` - Database credentials
- `api` - API keys and endpoints
- `ssh` - SSH host, port, username
- `github` - GitHub tokens

#### **Step 1.3: Inject Tokens into Code**
```python
# From: app/injection_engine.py

InjectionEngine(repo_path='./sample-project-basic')
  └─> find_code_files()  # Find all .py, .js, .ts files
  └─> find_injection_points_python()  # Find good places to inject
      └─ After imports (looks natural, bugs overlooked)
      └─ Before function definitions
      └─ Inside class definitions
  └─> inject_into_file()  # Add token as comment

# Result - file changes from this:
def authenticate():
    username = "admin"
    password = "real_password_123"

# To this:
# OLD_AWS_ACCESS_KEY_ID=AKIA4X5Y6Z7A8B9C0D1E
# OLD_AWS_SECRET_ACCESS_KEY=aB1+cD2/eF3+gH4/iJ5+kL6/mN7+oPq8r

def authenticate():
    username = "admin"
    password = "real_password_123"
```

**Why this approach?**
- Comments look like old credentials (natural)
- Won't break code syntax
- Attackers looking for secrets will find them
- Looks like a development artifact (accidentally left in)

---

### **PHASE 2: ATTACK DETECTION & LOGGING**

#### **Step 2.1: Attacker Discovers Fake Token**
```
Attacker finds the injected fake AWS credentials in your code.
They try to use it thinking they'll get AWS access.
```

#### **Step 2.2: Honeypot Trap Triggered**
When attacker tries to use fake credentials:
```bash
# Attacker attempts to use fake AWS key
aws s3 ls --aws-access-key-id AKIA4X5Y6Z7A8B9C0D1E \
         --aws-secret-access-key aB1+cD2/eF3+gH4/iJ5+kL6/mN7+oPq8r

# OR tries SSH honeypot
ssh -i fake_key.pem honeyuser@honeypot.example.com:2222

# OR connects to fake database
mysql -h honeypot.local -P 3307 -u fake_db_admin -p'password'
```

#### **Step 2.3: AttackLog Created**
```python
# From: app/realtime_event_processor.py

attack_log = AttackLog(
    honeypot_type='aws',  # Or 'ssh', 'db', 'web'
    source_ip='192.168.1.100',  # Attacker's IP
    user_agent='AWS CLI v2.13.0',
    request_method='POST',
    request_path='/sts:AssumeRole',
    timestamp=datetime.utcnow(),
    severity='MEDIUM',  # Will be updated by analysis
    attack_metadata={
        'access_key': 'AKIA4X5Y6Z7A8B9C0D1E',
        'service': 'sts',
        'region': 'us-east-1'
    }
)

# Token is marked as triggered
honeytoken.is_triggered = True
honeytoken.triggered_at = datetime.utcnow()
honeytoken.triggered_by_ip = '192.168.1.100'
honeytoken.triggered_by_user_agent = 'AWS CLI v2.13.0'
```

---

### **PHASE 3: INTELLIGENT ANALYSIS**

The `incident_orchestrator.py` now runs a **full multi-stage analysis pipeline**:

#### **Stage 1: Anomaly Detection**
```python
# From: app/anomaly_detector.py

anomaly_engine.extract_features(attack_logs)
# Features extracted:
{
    'hour_of_day': 2,  # Attack at 2 AM (unusual for normal users)
    'day_of_week': 5,  # Friday night
    'request_frequency_per_hour': 25,  # Very high
    'unique_ips_accessed_from': 1,  # Single IP (concentrated)
    'avg_time_between_accesses': 2.4,  # Very fast (bot-like)
    'user_agent_entropy': 0.92,  # High variety in user agents
    'geolocation_distance_from_baseline': 5000  # From different country
}

# ML Models: Isolation Forest + Local Outlier Factor (LOF)
anomaly_score = 0.87  # 0-1 scale, 1 = most anomalous
is_anomalous = True   # Both models agree something is wrong
anomaly_reason = "Access from new geographic location at unusual hour with bot-like behavior"
```

**What it detects:**
- ✅ Attacks at odd hours (3 AM, weekends)
- ✅ Rapid repeated access attempts
- ✅ Access from new geographic locations
- ✅ Unusual user agent patterns
- ✅ Concentrated vs distributed access

#### **Stage 2: Kill Chain Mapping & Severity**
```python
# From: app/kill_chain_analyzer.py

kill_chain_mapper.classify_attack(attack_log)
# Maps to MITRE ATT&ACK framework:
{
    'mitre_tactic': 'credential_access',  # T1110 Brute Force
    'mitre_technique': 'T1110.001',  # Password Guessing
    'kill_chain_phase': 'INITIAL_ACCESS' → 'CREDENTIAL_ACCESS',
    'confidence': 0.95
}

# Dynamic Severity Calculation:
base_score = 0.6  # Kill chain phase base
+ anomaly_multiplier = 1.45  # High anomaly * 1.45
+ repeat_offender = 1.2x  # Same IP seen before
+ geographic_anomaly = 1.4x  # New country
= FINAL_SEVERITY_SCORE = 8.5/10 (CRITICAL)

severity_level = 'CRITICAL'
severity_reasons = [
    "Credential access attempt on fake AWS key",
    "Unusual access time (2 AM Friday)",
    "Rapid consecutive attempts (25/hour)",
    "Access from new geographic region",
    "Detected evasion techniques"
]
```

**Kill Chain Phases:**
1. **Reconnaissance** (0.2) - Gathering information
2. **Weaponization** (0.3) - Preparing tools
3. **Delivery** (0.4) - Malware/exploit delivery
4. **Exploitation** (0.6) - Vulnerability exploitation
5. **Installation** (0.7) - Backdoor installation
6. **Command & Control** (0.8) - C2 channel established
7. **Actions on Objectives** (1.0) - Data exfiltration

#### **Stage 3: Threat Intelligence Enrichment**
```python
# From: app/threat_intel/ip_reputation.py

ip_reputation = check_ip_reputation('192.168.1.100')
# Returns:
{
    'ip_address': '192.168.1.100',
    'reputation_score': 0.78,  # 0=clean, 1=malicious
    'threat_level': 'HIGH',
    'is_vpn': True,  # Attacker using VPN
    'is_datacenter': False,
    'is_proxy': True,  # Using proxy to hide
    'threat_feeds': [
        'AbuseIPDB: 45 reports',
        'VirusTotal: In 8/92 blacklists',
        'Shodan: Port 22 open, SSH service detected'
    ],
    'geolocation': {
        'country': 'Russia',
        'city': 'Moscow',
        'coordinates': (55.75, 37.62)
    }
}
```

#### **Stage 4: Honeypot Evasion Detection**
```python
# From: app/deception/honeypot_evasion_detection.py

evasion_detector.detect_evasion_attempts(
    user_input='whoami; docker ps; nmap -p 22,3306 localhost',
    user_agent='curl/7.64.1',
    source_ip='192.168.1.100'
)
# Returns:
{
    'is_evasion': True,
    'evasion_type': 'fingerprint_detection',
    'techniques_detected': [
        'whoami - Reconnaissance command',
        'docker ps - VM/Container detection',
        'nmap - Network scanning tool'
    ],
    'evasion_score': 0.85,  # High likelihood of evasion
    'severity': 'CRITICAL',
    'explanation': 'Attacker trying to fingerprint honeypot environment'
}
```

---

### **PHASE 4: ALERTS & RESPONSES**

#### **Step 4.1: Alert Creation**
```python
# From: app/realtime_event_processor.py

alert = Alert(
    alert_type='HONEYTOKEN_TRIGGERED',
    severity='CRITICAL',
    title='AWS Honeytoken Accessed from Suspicious IP',
    message='''
    CRITICAL SECURITY EVENT
    
    Honeytokens: AKIA4X5Y6Z7A8B9C0D1E
    Source IP: 192.168.1.100 (Moscow, Russia)
    Time: 2024-03-22 02:15:34 UTC
    Detection Method: Anomaly detection + Kill chain mapping
    
    Attack Pattern: Credential Access (T1110)
    Kill Chain Phase: Initial Access
    Severity Score: 8.5/10
    
    Evasion Detected: Yes
    Is VPN/Proxy: Yes
    Threat Level: CRITICAL
    
    Recommendations:
    - Block IP immediately
    - Rotate all AWS keys
    - Review CloudTrail logs
    - Check for lateral movement
    '''
)

alert.created_at = datetime.utcnow()
session.add(alert)
session.commit()
```

#### **Step 4.2: Notifications Sent**
```python
# From: app/integrations.py

# Alert sent via multiple channels:

1. EMAIL
   To: security-team@company.com
   Subject: 🚨 CRITICAL: Honeytoken Accessed from Russia
   Body: [Full alert details above]

2. SLACK
   Channel: #security-incidents
   Message: 
   ⚠️ CRITICAL ALERT
   Honeytoken triggered: AKIA4X5Y6Z7A8B9C0D1E
   From: 192.168.1.100 (Russia) 🇷🇺
   Kill Chain: CREDENTIAL_ACCESS (T1110)
   Severity: 8.5/10
   [View Details] → http://dashboard.example.com/alerts/alert-id

3. GITHUB ISSUE (Optional)
   Title: [SECURITY] Honeytoken Breach Detected
   Body: Full incident report
   Assignees: security-team
   Labels: critical, breach, investigation

4. WEBHOOK
   POST to external SIEM/SOC system
```

#### **Step 4.3: Automated Response**
```python
# From: app/auto_response.py

# If severity >= CRITICAL:

1. BLOCK IP
   - Added to Redis blocklist immediately
   - Key: autohoneyx:blocklist:{ip}
   - TTL: 24 hours (configurable)
   - Result: All connections from 192.168.1.100 rejected

2. CREATE AUDIT TRAIL
   - Hash-chained events (immutable)
   - Event 1 Hash: hash(Event0 + action + timestamp)
   - Event 2 Hash: hash(Event1 Hash + action + timestamp)
   - Stored in DB for forensics

3. TRIGGER PLAYBOOK
   From: app/playbook_engine.py
   Playbook: "credential_compromise.yml"
   
   Actions:
   - Snapshot entire filesystem (evidence preservation)
   - Disable API keys for breached service
   - Notify AWS account owner
   - Begin incident response process
   - Create ticket in Jira: "Honeytoken Breach #12345"
```

---

## **PHASE 5: VISIBILITY & DASHBOARDS**

### **Real-Time Dashboard Displays:**

```
┌─────────────────────────────────────────────────────────────┐
│  🍯 AUTOHONEYX DASHBOARD                                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  📊 QUICK STATS                                              │
│  ├─ Active Honeytokens: 247                                 │
│  ├─ Honeypots Running: 5 (SSH, Web, DB x3)                 │
│  ├─ Triggered This Week: 12 attacks                         │
│  └─ Critical Alerts: 2 (unread)                             │
│                                                               │
│  🔴 LATEST INCIDENTS                                        │
│  ├─ [CRITICAL] AWS Token Accessed (Moscow) - 5 min ago     │
│  │   └─ IP Blocked for 24h ✓                               │
│  ├─ [HIGH] SSH Brute Force Detected - 15 min ago           │
│  │   └─ 145 attempts blocked                               │
│  └─ [MEDIUM] Unusual Access Pattern - 2 hours ago          │
│      └─ Marked for review                                   │
│                                                               │
│  📈 ATTACK TIMELINE                                         │
│  ├─ Last 24 Hours: 34 incidents                            │
│  ├─ Trend: ↑ 15% increase from last week                   │
│  └─ Peak Time: 2-3 AM UTC                                  │
│                                                               │
│  🗺️ GEOGRAPHIC DISTRIBUTION                               │
│  ├─ Russia: 12 attacks                                     │
│  ├─ China: 8 attacks                                       │
│  ├─ US (VPN): 6 attacks                                    │
│  └─ Other: 8 attacks                                       │
│                                                               │
│  🎯 THREAT SEVERITY BREAKDOWN                              │
│  ├─ 🔴 CRITICAL: 2 (9%)                                   │
│  ├─ 🟠 HIGH: 6 (27%)                                       │
│  ├─ 🟡 MEDIUM: 18 (82%)                                    │
│  └─ 🔵 LOW: 8 (36%)                                        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### **Detailed Incident View:**
```
┌─────────────────────────────────────────────────────────────┐
│  INCIDENT #12345: AWS Honeytoken Access                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  TIMELINE                                                    │
│  ├─ 02:15:34 Attack detected from 192.168.1.100           │
│  ├─ 02:15:35 Anomaly detection: Score 0.87                │
│  ├─ 02:15:36 Kill chain mapped: CREDENTIAL_ACCESS         │
│  ├─ 02:15:37 Severity calculated: 8.5/10 CRITICAL         │
│  ├─ 02:15:38 IP reputation enriched (Russia, VPN)         │
│  ├─ 02:15:39 Evasion detected: Docker/VM fingerprinting   │
│  ├─ 02:15:40 Alert created and sent                       │
│  └─ 02:15:41 IP blocked, playbook triggered               │
│                                                               │
│  ANALYSIS RESULTS                                            │
│  ├─ Anomaly Score: 0.87 (High)                             │
│  ├─ MITRE Tactic: credential_access                        │
│  ├─ MITRE Technique: T1110.001 (Password Guessing)         │
│  ├─ Kill Chain Phase: Initial Access → Credential Access  │
│  ├─ Evasion Type: Fingerprint Detection                    │
│  └─ Threat Level: CRITICAL                                 │
│                                                               │
│  SOURCE INFORMATION                                         │
│  ├─ IP Address: 192.168.1.100                             │
│  ├─ Geolocation: Moscow, Russia                            │
│  ├─ VPN Detected: Yes (ExpressVPN)                        │
│  ├─ Proxy Detected: Yes                                    │
│  ├─ ASN: AS39798 (Yandex)                                 │
│  ├─ Reputation: 0.78/1.0 (Malicious)                      │
│  └─ Threat Feeds: AbuseIPDB (45 reports), VirusTotal      │
│                                                               │
│  AUTOMATED RESPONSE                                        │
│  ├─ ✓ IP Blocked: 24 hours                                │
│  ├─ ✓ Alert Sent: Email, Slack, Teams                     │
│  ├─ ✓ Audit Log: Hash-chained                             │
│  ├─ ✓ Evidence: Snapshot created                          │
│  ├─ ✓ Jira Ticket: SEC-45678 created                      │
│  └─ → Playbook: credential_compromise.yml running         │
│                                                               │
│  REMEDIATION                                                │
│  ├─ [ ] Rotate AWS credentials                            │
│  ├─ [ ] Review CloudTrail logs                            │
│  ├─ [ ] Check for lateral movement                        │
│  ├─ [ ] Force re-authentication for users                 │
│  └─ [ ] Update incident report                            │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## **API ENDPOINTS FOR DEMO**

### **Interactive API Testing at: http://localhost:8000/docs**

```python
# 1. GENERATE HONEYTOKEN
POST /api/tokens/generate
{
    "token_type": "aws",  # or "db_postgresql", "api", "ssh"
    "count": 3
}
Response:
{
    "tokens": [
        {
            "id": "token-123",
            "token_id": "a1b2c3d4",
            "token_type": "aws",
            "access_key_id": "AKIA4X5Y6Z7A8B9C0D1E",
            "created_at": "2024-03-22T02:00:00Z"
        }
    ]
}

# 2. INJECT TOKENS
POST /api/inject
{
    "repo_path": "./sample-project-basic",
    "token_types": ["aws", "db_postgresql"],
    "files_per_type": 2
}
Response:
{
    "injections": 4,
    "files_modified": ["src/config.py", "src/database.py"],
    "message": "4 honeytokens injected successfully"
}

# 3. CHECK IP REPUTATION
POST /api/threat-intel/check-ip
{
    "ip_address": "192.168.1.100"
}
Response:
{
    "ip": "192.168.1.100",
    "reputation_score": 0.78,
    "threat_level": "HIGH",
    "is_vpn": true,
    "geolocation": {
        "country": "Russia",
        "city": "Moscow"
    }
}

# 4. DETECT EVASION
POST /api/honeypot/detect-evasion
{
    "user_input": "whoami; docker ps; nmap localhost",
    "user_agent": "curl/7.64.1",
    "source_ip": "192.168.1.100"
}
Response:
{
    "is_evasion": true,
    "evasion_type": "fingerprint_detection",
    "techniques": ["whoami", "docker ps"],
    "evasion_score": 0.85,
    "severity": "CRITICAL"
}

# 5. GET ALERTS
GET /api/alerts?severity=CRITICAL&limit=10
Response:
{
    "alerts": [
        {
            "id": "alert-123",
            "alert_type": "HONEYTOKEN_TRIGGERED",
            "severity": "CRITICAL",
            "title": "AWS Honeytoken Accessed",
            "created_at": "2024-03-22T02:15:34Z",
            "is_sent": true
        }
    ]
}

# 6. GET INCIDENT DETAILS
GET /api/incidents/{incident_id}
Response:
{
    "incident_id": "incident-123",
    "timestamp": "2024-03-22T02:15:34Z",
    "source_ip": "192.168.1.100",
    "kill_chain_phase": "credential_access",
    "severity_score": 8.5,
    "severity_level": "CRITICAL",
    "anomaly_score": 0.87,
    "is_anomalous": true,
    "evasion_detected": true,
    "automated_response": {
        "ip_blocked": true,
        "block_expires_at": "2024-03-23T02:15:34Z"
    }
}
```

---

## **KEY COMPONENTS SUMMARY**

| Component | Purpose | Location |
|-----------|---------|----------|
| **Honeytoken Generator** | Creates fake credentials | `app/honeytoken_generator.py` |
| **Injection Engine** | Injects tokens into code | `app/injection_engine.py` |
| **Anomaly Detector** | ML-based pattern detection | `app/anomaly_detector.py` |
| **Kill Chain Analyzer** | MITRE ATT&CK mapping | `app/kill_chain_analyzer.py` |
| **Threat Intel** | IP reputation, geolocation | `app/threat_intel/ip_reputation.py` |
| **Evasion Detection** | Honeypot fingerprinting detection | `app/deception/honeypot_evasion_detection.py` |
| **Incident Orchestrator** | Coordinates all engines | `app/incident_orchestrator.py` |
| **Event Processor** | Real-time event handling | `app/realtime_event_processor.py` |
| **Auto Response** | Automated blocking & alerts | `app/auto_response.py` |
| **Dashboard** | Web UI for management | `dashboard/app.py` |
| **REST API** | Integration endpoint | `app/realtime_api.py` |

---

## **COMPLETE DEMO SCENARIO**

### **Setup (2 minutes)**
1. Open PowerShell in `AutoHoneyX` directory
2. Run: `.\START_API.bat`
3. Wait for "Application startup complete"
4. Open browser: `http://localhost:8000/docs`

### **Demo Actions (5 minutes)**

**Step 1: Generate Token (1 min)**
- POST `/api/tokens/generate` with `token_type=aws`
- Show generated fake AWS credentials
- Explain why it's fake (format but would never work)

**Step 2: Simulate Attack (1 min)**
- Call POST `/api/threat-intel/check-ip` with attacker IP
- Show IP reputation: VPN, proxy, malicious
- Explain real IP tracking

**Step 3: Detect Evasion (1 min)**
- POST `/api/honeypot/detect-evasion`
- Pass commands like "whoami; docker ps; nmap"
- Show evasion score and techniques detected

**Step 4: View Incident**
- GET `/api/incidents/{id}`
- Show full analysis:
  - Anomaly score (0.87)
  - Kill chain phase (CREDENTIAL_ACCESS)
  - Severity (8.5/10 CRITICAL)
  - Automated response (IP blocked)

**Step 5: Dashboard**
- Open `http://localhost:8501`
- Show Streamlit dashboard with:
  - Active tokens
  - Latest incidents
  - Attack timeline
  - Geographic distribution

---

## **Key Strengths to Highlight**

✅ **Automated Secret Detection** - Catches when fake creds are used  
✅ **ML-Powered Analysis** - Detects unknown attack patterns  
✅ **MITRE Mapping** - Explains attack in industry standard  
✅ **Real-Time Response** - Blocks IP within milliseconds  
✅ **Audit Trail** - Immutable hash-chained events  
✅ **Multi-Layer Alerts** - Email, Slack, GitHub, webhooks  
✅ **Threat Intelligence** - Enriches with reputation, geolocation  
✅ **Honeypot Aware** - Detects evasion/fingerprinting  
✅ **Enterprise Ready** - Docker, Kubernetes, cloud deployment  
✅ **Extensible** - Easy to add new token types, honeypots, playbooks  

---

## **Security Posture**

- **Defense in Depth**: Multiple detection layers
- **Zero Trust**: Assumes all access is suspicious
- **Forensics**: Every event recorded and hash-chained
- **Automation**: Reduces incident response time to seconds
- **Intelligence**: Protects against sophisticated attackers
