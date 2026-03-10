# 🚀 AUTOHONEYX PROJECT RUNNING - SETUP GUIDE

Your security enhancements have been automatically implemented! Here's what was done and how to run it:

## **✅ COMPLETED IMPLEMENTATIONS**

### **Security Modules Created:**
1. ✅ `app/security/validators.py` - Input validation & sanitization
2. ✅ `app/security/auth.py` - JWT authentication & RBAC
3. ✅ `app/security/encryption.py` - Data encryption at rest
4. ✅ `app/threat_intel/ip_reputation.py` - IP reputation checking (AbuseIPDB, VirusTotal)
5. ✅ `app/threat_intel/mitre_attack.py` - MITRE ATT&CK framework mapping
6. ✅ `app/deception/honeypot_evasion_detection.py` - Sophisticated evasion detection
7. ✅ `LAYMANS_GUIDE.md` - Easy-to-understand feature explanations
8. ✅ `requirements.txt` - Updated with security dependencies

### **New Dependencies Added:**
- python-jose + cryptography (JWT authentication)
- passlib + bcrypt (Password hashing)
- slowapi (Rate limiting)
- pydantic[email] (Enhanced validation)
- yara-python (Malware detection)
- fastapi + uvicorn (Modern API framework)

---

## **🐳 OPTION 1: Run with Docker (Recommended)**

### **Step 1: Start Docker Desktop**

**Automatic (PowerShell as Admin):**
```powershell
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
Start-Sleep -Seconds 45  # Wait for Docker to start
```

**Manual:**
1. Click Start Menu
2. Search for "Docker Desktop"
3. Click to launch
4. Wait ~45 seconds for the Docker whale icon to appear in system tray
5. Proceed to Step 2

### **Step 2: Run the Full Stack**

```powershell
cd "C:\Users\bhave\Downloads\AutoHoneyX\AutoHoneyX"
docker-compose up -d
```

### **Step 3: Access the Dashboard**

Once containers are running (wait 20-30 seconds):
- **Dashboard**: http://localhost:8501
- **API Docs**: http://localhost:8000/docs
- **API Health**: http://localhost:8000/health

### **Verify All Services Running:**
```powershell
docker-compose ps
```

Expected output (all HEALTHY):
```
autohoneyx_db                 postgres:15-alpine    HEALTHY    5432
autohoneyx_api                app                    UP         8000  
autohoneyx_app               streamlit              UP         8501
autohoneyx_monitor           monitoring             UP         (background)
autohoneyx_ssh_honeypot      ssh trap               UP         2222
autohoneyx_web_honeypot      web trap               UP         8080
autohoneyx_db_honeypot       db trap                UP         3307
```

---

## **💻 OPTION 2: Run Locally (Without Docker)**

If Docker won't start, run locally with Python:

### **Step 1: Set Up Environment**

```powershell
cd "C:\Users\bhave\Downloads\AutoHoneyX\AutoHoneyX"

# Use SQLite for local development
$env:DATABASE_URL = "sqlite:///autohoneyx_dev.db"
$env:ENVIRONMENT = "development"
$env:LOG_LEVEL = "INFO"
```

### **Step 2: Install Dependencies**

```powershell
pip install -r requirements.txt
```

### **Step 3: Initialize Database**

```powershell
python run.py init-db
```

### **Step 4: Start Services**

**In Terminal 1 (API Server):**
```powershell
$env:DATABASE_URL = "sqlite:///autohoneyx_dev.db"
uvicorn app.realtime_api:app --host 0.0.0.0 --port 8000 --reload
```

**In Terminal 2 (Dashboard):**
```powershell
$env:DATABASE_URL = "sqlite:///autohoneyx_dev.db"
streamlit run dashboard/app.py --logger.level=info
```

**In Terminal 3 (Monitoring Service):**
```powershell
$env:DATABASE_URL = "sqlite:///autohoneyx_dev.db"
python -m monitoring.monitor_service
```

### **Step 5: Access Dashboard**

Open: http://localhost:8501

---

## **📊 QUICK START - First Steps**

Once dashboard loads (http://localhost:8501):

### **1. Generate Honeytokens**
- Sidebar → **Honeytokels**
- Click **Generate** tab
- Choose token types (check all: AWS, Database, API, SSH, GitHub, Slack)
- Click "Generate 6 Tokens"
- You'll see them displayed

### **2. Inject into Code**
- Click **Inject** tab
- Repository Path: `test-project` (it's in the project)
- Files per type: `3`
- Click "Preview" to see changes
- Click "Inject Tokens"

### **3. Monitor Attacks**
- Click **Attack Logs** tab
- (You'll see any attacks captured here)

- Click **Alerts** tab
- (Real-time security alerts appear here)

### **4. View Behavior Analysis**
- Click **Behavior Analysis** tab
- See ML-powered attack predictions

### **5. Settings**
- Click **Settings** tab
- Configure:
  - Slack webhook (optional)
  - Email alerts (optional)
  - Alert sensitivity levels

---

## **🔐 NEW SECURITY FEATURES EXPLAINED**

### **1. JWT Authentication**
- All API endpoints now require a Bearer token
- Tokens expire after 30 minutes
- Role-based access (ADMIN, ANALYST, VIEWER)

**Example API call:**
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/api/tokens
```

### **2. Rate Limiting**
- API endpoints limited to prevent brute-force
- `/api/tokens/generate`: 10 requests/minute
- `/api/inject`: 5 requests/minute
- `/api/scan`: 20 requests/hour

### **3. Input Validation**
- All requests validated using Pydantic
- Path traversal attacks blocked
- Invalid characters rejected

### **4. Data Encryption**
- Sensitive tokens encrypted at rest
- Using Fernet (symmetric encryption)
- Decrypted only when needed

### **5. Threat Intelligence Integration**
- IP reputation checks (AbuseIPDB, VirusTotal)
- Geolocation tracking
- Evasion technique detection
- MITRE ATT&CK mapping

---

## **🎯 TESTING THE SYSTEM**

### **Test 1: Create & Inject Token**
```
1. Dashboard → Honeytokels → Generate
2. Generate AWS token (e.g., AKIA2024FAKE123456)
3. Click Inject tab
4. Set repository path: "test-project"
5. Click Inject
6. Check Attack Logs (nothing yet - good!)
```

### **Test 2: Simulate Attack**
```
1. Go to injected file: test-project/src/app.py
2. Find the injected comment: # AWS_ACCESS_KEY_ID=XXXXX
3. Copy the fake AWS key
4. Go to API tab → Try posting to /api/attack-logs/analyze
5. System logs it as suspicious activity
```

### **Test 3: Check Evasion Detection**
```
1. Dashboard → API Docs (http://localhost:8000/docs)
2. Expand POST /api/honeypot/detect-evasion
3. Try Request Body:
   {
     "user_input": "whoami; uname -a; docker ps; nmap -sV",
     "user_agent": "Mozilla/5.0"
   }
4. Response shows evasion score and detected techniques
```

---

## **📈 UNDERSTANDING THE ALERTS**

When you get an alert, it might say:

| Alert Type | What It Means | Severity |
|-----------|--------------|----------|
| SECRET_DETECTED | Code scanner found a secret | CRITICAL |
| HONEYPOT_TRIGGERED | Someone used a fake credential | CRITICAL |
| BRUTE_FORCE_DETECTED | Multiple failed auth attempts | HIGH |
| UNUSUAL_PATTERN | AI detected anomalous behavior | MEDIUM |
| EVASION_ATTEMPT | Attacker trying to fingerprint system | HIGH |
| SUSPICIOUS_IP | IP has bad reputation from threat intel | MEDIUM |

---

## **🛠️ TROUBLESHOOTING**

### **Issue: "Database connection refused"**
**Solution:** Set environment variable:
```powershell
$env:DATABASE_URL = "sqlite:///autohoneyx_dev.db"
```

### **Issue: "Port 8501 already in use"**
**Solution:** Kill process and restart:
```powershell
lsof -ti:8501 | xargs kill -9
streamlit run dashboard/app.py
```

### **Issue: "Module not found"**
**Solution:** Reinstall requirements:
```powershell
pip install --force-reinstall -r requirements.txt
```

### **Issue: Docker containers won't start**
**Solution:** Clean rebuild:
```powershell
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

## **📚 FILE STRUCTURE**

New security modules location:
```
app/
├── security/              # ← NEW
│   ├── validators.py     # Input validation
│   ├── auth.py           # JWT authentication
│   └── encryption.py     # Data encryption
├── threat_intel/         # ← NEW
│   ├── ip_reputation.py  # IP threat checking
│   └── mitre_attack.py   # ATT&CK mapping
├── deception/            # ← NEW
│   └── honeypot_evasion_detection.py  # Evasion detection
├── realtime_api.py       # Main API
├── models.py             # Database models
└── ...
```

---

## **🎓 LEARNING RESOURCES**

1. **Understanding Honeypots**: See `LAYMANS_GUIDE.md`
2. **Security Features**: See `SECURITY_ENHANCEMENTS.md`
3. **Full Architecture**: See `PROJECT_STRUCTURE.md`
4. **Deployment Guide**: See `REALTIME_DEPLOYMENT_GUIDE.md`

---

## **⚠️ IMPORTANT NOTES**

1. **Demo API Keys**: Threat intelligence uses demo keys by default
   - Set `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` env vars for real data
   
2. **Encryption Key**: Generated on first run
   - Store `ENCRYPTION_MASTER_KEY` safely in production
   
3. **JWT Secret**: Set custom secret in production
   - Set `JWT_SECRET_KEY` environment variable
   
4. **Rate Limiting**: In-memory storage (use Redis in production)
   - Resets on service restart

---

## **✨ NEXT STEPS**

1. ✅ **Read the Layman's Guide** → `LAYMANS_GUIDE.md`
2. ✅ **Start the project** (Docker or Local)
3. ✅ **Generate some honeytokels**
4. ✅ **Inject them into test-project**
5. ✅ **Monitor the dashboard**
6. ✅ **Test the security features**
7. ✅ **Configure alerts** (Slack, Email)
8. ✅ **Deploy to cloud** (See SECURITY_ENHANCEMENTS.md for AWS/Azure/GCP)

---

**🎉 AutoHoneyX is ready to protect your systems!**

For detailed security enhancements, cloud deployment, and advanced configurations, see:
- 📖 `SECURITY_ENHANCEMENTS.md` - Production-ready security implementations
- ☁️ Terraform IaC examples included
- 🔗 Kubernetes deployment guides included

---

*Run one of the options above to get started!*
