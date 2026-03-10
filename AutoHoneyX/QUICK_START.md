# 🍯 AUTOHONEYX - QUICK START (5 MINUTES)

## **What You Have**

✅ **Complete honeypot security system** with enterprise-grade protections
✅ **6 advanced security modules** ready to use
✅ **Full documentation** in plain English + technical
✅ **Cloud deployment templates** (AWS, Azure, GCP, Kubernetes)
✅ **Working API** for integration

---

## **START HERE - 3 Easy Steps**

### **Step 1: Start the API Server**

Open PowerShell in project directory:
```powershell
cd "C:\Users\bhave\Downloads\AutoHoneyX\AutoHoneyX"
.\START_API.bat
```

Wait for:
```
INFO:     Application startup complete
```

### **Step 2: Test It's Working**

Open in browser:
```
http://127.0.0.1:8000/docs
```

You'll see interactive API documentation. Try these endpoints:

**Test IP Reputation Check:**
1. Find "POST /api/threat-intel/check-ip"
2. Click "Try it out"
3. Enter: `{"ip_address": "1.1.1.1"}`
4. Click "Execute"
5. See reputation score, VPN detection, threat level

**Test Evasion Detection:**
1. Find "POST /api/honeypot/detect-evasion"
2. Click "Try it out"
3. Enter: `{"user_input": "whoami; docker ps; nmap", "user_agent": "Mozilla"}`
4. Click "Execute"
5. See what attack techniques were detected

### **Step 3: Understand the Features**

Read these in order (each 5 minutes):

1. **LAYMANS_GUIDE.md** - What is it? How does it work?
2. **SETUP_AND_RUN.md** - How to deploy locally or Docker
3. **SECURITY_ENHANCEMENTS.md** - Advanced features & cloud options

---

## **Understanding Each Security Module**

Once API is running, call these endpoints to test:

### **1️⃣ Input Validation**
*Prevents malicious input from breaking the system*

```bash
# Valid input (accepted)
curl -X POST http://127.0.0.1:8000/api/validate
  -d '{"repo_path": "test-project/src", "token_types": ["aws"]}'

# Invalid input (rejected as attack)
curl -X POST http://127.0.0.1:8000/api/validate
  -d '{"repo_path": "../../etc/passwd", "token_types": ["malware"]}'
```

### **2️⃣ JWT Authentication** 
*Ensures only authorized users access the system*

```bash
# Get authentication token
curl -X POST http://127.0.0.1:8000/api/auth/token \
  -d '{"user_id": "analyst1", "role": "analyst"}'

# Response: {"access_token": "eyJ0eXAi...", "token_type": "bearer"}

# Use token to access protected endpoint
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:8000/api/protected-endpoint
```

### **3️⃣ Encryption at Rest**
*Protects sensitive data even if database is stolen*

In code, sensitive fields are encrypted:
```python
class Honeytoken(Base):
    token_value = Column(EncryptedString(500))  # Automatically encrypted!
    api_key = Column(EncryptedString(255))      # Automatically encrypted!
```

Database stores: `gAAAAABjsomeencryptedtext...`  
Application sees: `AKIA2024FAKE123456`

### **4️⃣ IP Reputation Checking**
*Knows if attacker's IP is known bad actor*

```bash
curl -X POST http://127.0.0.1:8000/api/threat-intel/check-ip \
  -d '{"ip_address": "192.168.1.1"}'

# Response:
{
  "ip": "192.168.1.1",
  "abuseipdb_score": 45,           # 0-100 (higher = worse)
  "virustotal_detections": {       # How many security vendors flagged it
    "malicious": 5,
    "suspicious": 2
  },
  "is_malicious": false,           # Recommendation
  "risk_level": "MEDIUM"
}
```

### **5️⃣ MITRE ATT&CK Mapping**
*Classifies attacks using industry standard* 

```bash
curl -X POST http://127.0.0.1:8000/api/mitre/map-attack \
  -d '{"attack_category": "brute_force"}'

# Response:
{
  "severity": "HIGH",
  "tactics": ["Credential Access"],
  "techniques": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "url": "https://attack.mitre.org/techniques/T1110/",
      "mitigation": "Implement MFA, account lockout..."
    }
  ]
}
```

### **6️⃣ Honeypot Evasion Detection**
*Catches attackers trying to detect honeypots*

```bash
curl -X POST http://127.0.0.1:8000/api/honeypot/detect-evasion \
  -d '{
    "user_input": "if docker ps; then echo HONEYPOT; fi",
    "user_agent": "Mozilla"
  }'

# Response:
{
  "is_evasion_attempt": true,           # RED FLAG!
  "evasion_score": 0.85,                # High score = sophisticated attacker
  "risk_level": "CRITICAL",
  "techniques_detected": [
    "fingerprint_detection",            # Trying to detect honeypot
    "reconnaissance"
  ],
  "recommendation": "Immediate alerts: Sophisticated attacker detected..."
}
```

---

## **See It All in Action**

### **Real Attack Scenario - Step by Step**

1. **Attacker finds your code** with fake AWS key: `AKIA2024FAKE123456`

2. **They try to use it:**
   ```bash
   aws s3 ls --access_key AKIA2024FAKE123456 --secret_key ...
   ```

3. **AWS rejects** (key doesn't exist) but system logs it

4. **AutoHoneyX detects:**
   - API validates the attempted use ✅
   - Checks attacker's IP reputation ✅  
   - Maps to MITRE T1110 (Brute Force) ✅
   - Detects evasion patterns (if any) ✅
   - Creates alert with all context ✅

5. **You get notified:**
   ```
   CRITICAL Alert: Honeypot Token Used
   - Fake AWS Key: AKIA2024FAKE123456
   - Source IP: 203.0.113.7
   - IP Reputation: MEDIUM (30/100 from AbuseIPDB)
   - Attack Type: Credential Access / T1110
   - Geolocation: Unknown (VPN Detected)
   - Timestamp: 2026-02-23 18:45:32 UTC
   ```

6. **You respond immediately**

---

## **Where's What**

| What | Where | How to Use |
|------|-------|-----------|
| **Start API** | START_API.bat | Double-click or `.\START_API.bat` |
| **API Docs** | http://127.0.0.1:8000/docs | Click endpoints to test |
| **Explanations** | LAYMANS_GUIDE.md | Read in any text editor |
| **Setup Help** | SETUP_AND_RUN.md | Follow for Docker/Local setup |
| **Security Details** | SECURITY_ENHANCEMENTS.md | Technical implementation reference |
| **Cloud Deploy** | SECURITY_ENHANCEMENTS.md (Part 3) | Terraform IaC for AWS/Azure/GCP |
| **Security Code** | app/security/ | Source code, fully commented |
| **Threat Intel Code** | app/threat_intel/ | Source code, fully commented |
| **Evasion Detection** | app/deception/ | Source code, fully commented |

---

## **Common Tasks**

### **Task: Test JWT Authentication**
```powershell
# 1. Get token
$response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/auth/token" `
  -Method POST -Headers @{"Content-Type"="application/json"} `
  -Body '{"user_id":"admin","role":"admin"}'

$token = ($response.Content | ConvertFrom-Json).access_token

# 2. Use token for protected call
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/health" `
  -Headers @{"Authorization"="Bearer $token"}
```

### **Task: Check IP Reputation**
```bash
# Check if 8.8.8.8 (Google) is malicious
curl -X POST http://127.0.0.1:8000/api/threat-intel/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "8.8.8.8"}'

# Result should show clean - no threats
```

### **Task: Test Rate Limiting**
```bash
# Try to make 15 requests to /api/tokens/generate in 1 minute
# After 10 requests, you'll get: "429 Too Many Requests"
```

### **Task: Generate Demo Honeypot**
```bash
# Create fake AWS key
curl -X POST http://127.0.0.1:8000/api/tokens/generate \
  -d '{"token_type": "aws"}'

# Response: AKIA2024RANDOMK3YS generated
```

---

## **🎓 Learning Path**

**Hour 1: Understand Concepts**
- Read LAYMANS_GUIDE.md (all sections)
- View diagrams and examples
- Understand each feature

**Hour 2: Test Features**
- Start API server
- Try each endpoint at http://127.0.0.1:8000/docs
- Generate & inject tokens
- View results

**Hour 3: Deploy Options**
- Read SETUP_AND_RUN.md
- Choose Docker or Local setup
- Deploy to your environment
- Configure alerts (Slack/Email)

**Hour 4+: Production**
- Read SECURITY_ENHANCEMENTS.md Part 3
- Deploy to Cloud (AWS/Azure/GCP)
- Set up CI/CD security
- Monitor in production

---

## **🆘 Troubleshooting**

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run: `pip install -r requirements.txt` |
| Port 8000 in use | Run: `netstat -ano \| findstr :8000` then kill process |
| Database error | Delete `autohoneyx_dev.db`, restart to recreate |
| API won't start | Check Python version: `python --version` (need 3.8+) |
| Can't import modules | Ensure virtual env activated: `. .\venv\Scripts\Activate.ps1` |

---

## **Next: What To Do NOW**

1. ✅ Read this page (you're done!)
2. ✅ Run `.\START_API.bat`  
3. ✅ Visit http://127.0.0.1:8000/docs
4. ✅ Try "IP Reputation" endpoint
5. ✅ Read LAYMANS_GUIDE.md next

---

**That's it! You now have AutoHoneyX running with enterprise security. 🚀**

For questions, consult:
- **LAYMANS_GUIDE.md** - Easy explanations
- **SETUP_AND_RUN.md** - Setup help  
- **SECURITY_ENHANCEMENTS.md** - Technical details
- **API Docs** - Live at http://127.0.0.1:8000/docs

**Happy honeypot hunting! 🍯**
