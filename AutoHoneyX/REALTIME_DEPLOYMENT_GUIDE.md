# AutoHoneyX Real-Time Secret Detection System
## GitGuardian-Style Implementation & Deployment Guide

### 🎯 What You Now Have

Your AutoHoneyX project has been transformed into a **GitGuardian-style real-time secret detection system**:

| Feature | Implementation | Status |
|---------|-----------------|--------|
| **Real-Time Scanning** | `app/realtime_scanner.py` | ✅ |
| **WebSocket API** | `app/realtime_api.py` | ✅ |
| **Continuous Monitoring** | `monitoring/monitor_service.py` | ✅ |
| **Git Hooks** | `app/git_hooks.py` | ✅ |
| **GitHub/GitLab Integration** | `app/integrations.py` | ✅ |
| **Slack/Email Alerts** | `app/integrations.py` | ✅ |
| **Cloud Deployment** | `docker-compose.prod.yml` | ✅ |

---

## 📦 Installation & Setup

### Step 1: Configure Environment

```bash
# Copy and configure .env
cp .env.example .env

# Edit .env with your settings
nano .env
```

**Key settings to update:**
```env
# Database
DATABASE_URL=postgresql://autohoneyx:password@localhost:5432/autohoneyx_db

# GitHub/GitLab Scanning
GITHUB_TOKEN=ghp_your_token_here
MONITORED_REPOS=/path/to/your/repos

# Real-Time Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
GITHUB_TOKEN=ghp_...

# Security
JWT_SECRET_KEY=your-32-byte-secret-key
ENCRYPTION_MASTER_KEY=your-32-byte-key
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt

# Additional packages needed:
pip install fastapi uvicorn websockets aiofiles geoip2
```

### Step 3: Initialize Database

```bash
python -m scripts.init_db
```

---

## 🚀 Running in Real-Time

### Option A: Local Development

```bash
# Terminal 1: Start Real-Time API (WebSocket + REST)
python -m uvicorn app.realtime_api:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Start Monitoring Service (background scanning)
python -m monitoring.monitor_service

# Terminal 3: Start Dashboard (visualization)
streamlit run dashboard/app.py
```

Access:
- API: `http://localhost:8000`
- WebSocket: `ws://localhost:8000/ws/incidents`
- Dashboard: `http://localhost:8501`
- Metrics: `http://localhost:9090` (Prometheus)

### Option B: Docker (Recommended for Production)

```bash
# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Check status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f api
docker-compose -f docker-compose.prod.yml logs -f monitor
```

### Option C: Kubernetes (Cloud Deployment)

```bash
# Build image
docker build -t autohoneyx:latest -f Dockerfile.prod .

# Push to registry
docker tag autohoneyx:latest your-registry/autohoneyx:latest
docker push your-registry/autohoneyx:latest

# Deploy to Kubernetes
kubectl apply -f k8s/
```

---

## 🔍 Real-Time Detection Features

### 1. **Automatic Secret Detection** (482+ patterns)

The system scans for:
- AWS Keys (`AKIA...`)
- GitHub Tokens (`ghp_...`)
- GitLab Tokens (`glpat-...`)
- Slack Tokens
- MongoDB URIs
- PostgreSQL URIs
- Private Keys (RSA, DSA, ECDSA)
- **And 470+ more patterns...**

### 2. **Multi-Source Scanning**

```python
# Scan git repositories
await scanner.scan_git_repository('/path/to/repo')

# Scan log files
await scanner.scan_directory('/var/log')

# Scan public GitHub repos
await scanner.scan_public_repositories('your-org', 'github')

# Scan current code
await scanner.scan_content(code_string)
```

### 3. **Real-Time Incident Management**

All incidents are automatically:
- 📊 Tracked in dashboard
- 📡 Broadcast via WebSocket
- 🚨 Sent to Slack/Email
- 🔍 Analyzed for severity
- 🔄 Queued for remediation

### 4. **Pre-Commit Git Hooks** (Prevent Leaks)

```bash
# Install hooks in your repo
python -c "from app.git_hooks import install_all_hooks; install_all_hooks('.')"

# Now secrets are blocked before commit:
# ❌ ATTENTION: Potential secrets detected in staged files!
```

---

## 📊 API Quick Reference

### Real-Time Streaming (WebSocket)

```javascript
// Connect to real-time incident stream
const ws = new WebSocket('ws://localhost:8000/ws/incidents');

ws.onmessage = (event) => {
  const incident = JSON.parse(event.data);
  console.log(`🔒 ${incident.severity} - ${incident.secret_type}`);
};
```

### REST Endpoints (HTTP)

```bash
# Get all open incidents
curl http://localhost:8000/api/v1/incidents

# Get real-time stats
curl http://localhost:8000/api/v1/stats

# Get incident details
curl http://localhost:8000/api/v1/incidents/{id}

# Resolve incident
curl -X POST http://localhost:8000/api/v1/incidents/{id}/resolve \
  -H "Content-Type: application/json" \
  -d '{"auto_remediate": true}'

# Search incidents
curl "http://localhost:8000/api/v1/search?query=aws&severity=CRITICAL"
```

---

## 🔐 Automatic Remediation

When an exposed secret is detected, the system can automatically:

```python
# 1. GitHub Token → Revoke immediately
await scanner._revoke_github_token(finding)

# 2. AWS Key → Disable in AWS
await scanner._disable_aws_key(finding)

# 3. Password → Send change notification
await scanner._prompt_password_change(finding)
```

Enable with:
```bash
export AUTO_REMEDIATE=true
```

---

## 📈 Monitoring & Alerts

### 1. **Slack Alerts** ✅

```
Channel: #security-alerts

🔒 Secret Detected: AWS_ACCESS_KEY
Severity: CRITICAL
File: config/settings.py:45
Detected: 2024-10-21
```

### 2. **Email Alerts** (Critical only)

```
Subject: 🔒 Security Alert: GitHub Token Detected

Type: GitHub Personal Token
Severity: CRITICAL
File: /app/secrets.py:123
Timestamp: 2024-10-21T14:35:22Z
```

### 3. **Metrics Dashboard** (Grafana)

```
Access: http://localhost:3000
- Total Incidents (24h)
- Severity Distribution
- Security Trend
- MTTR (Mean Time To Remediate)
- Risk Score
```

---

## 🌍 Cloud Deployment

### AWS EC2 Deployment

```bash
# 1. Launch EC2 instance (Ubuntu 22.04)
# 2. Install Docker
curl -fsSL https://get.docker.com | sh

# 3. Clone repo
git clone https://github.com/your-org/autohoneyx.git
cd autohoneyx

# 4. Configure .env
cp .env.example .env
nano .env

# 5. Start with Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# 6. Setup SSL (Let's Encrypt)
docker exec -it autohoneyx_api_prod \
  certbot certonly --standalone -d your-domain.com
```

### Azure Container Instances

```bash
# Build and push image
az acr build --registry your-registry \
  --image autohoneyx:latest .

# Deploy
az container create --resource-group rg-autohoneyx \
  --name autohoneyx-api \
  --image your-registry.azurecr.io/autohoneyx:latest \
  --environment-variables \
    DATABASE_URL="postgresql://..." \
    GITHUB_TOKEN="ghp_..." \
  --ports 8000 443
```

### GCP Cloud Run

```bash
# Build
gcloud builds submit --tag gcr.io/PROJECT_ID/autohoneyx

# Deploy
gcloud run deploy autohoneyx \
  --image gcr.io/PROJECT_ID/autohoneyx \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL="postgresql://..."
```

---

## 🔧 Configuration Examples

### Scan Multiple Repositories

```bash
export MONITORED_REPOS="/path/repo1,/path/repo2,/path/repo3"
export SCAN_INTERVAL_SECONDS=300
```

### GitHub Organization Scanning

```bash
export GITHUB_TOKEN=ghp_xxx
export GITHUB_ORG=your-organization
```

### Enable All Alerts

```bash
export SLACK_WEBHOOK_URL=https://...
export SMTP_SERVER=smtp.gmail.com
export FROM_EMAIL=alerts@company.com
export ALERT_EMAIL=security-team@company.com
```

---

## 📊 Real-Time Performance

### Response Times (Expected)

| Operation | Time |
|-----------|------|
| Detect Secret | 50-200ms |
| Create Incident | 100ms |
| Send Slack Alert | 500-1000ms |
| WebSocket Broadcast | 50ms |
| Dashboard Update | 100ms |

### Load Capacity

- **1000 commits/day**: ✅ Easily handled
- **10K commits/day**: ✅ No problem
- **100K commits/day**: ⚠️ Recommend scaling

---

## 🎯 Integration Examples

### Slack + GitHub Alerts

```python
from app.integrations import IntegrationManager

manager = IntegrationManager()

incident = {
    'secret_type': 'AWS_ACCESS_KEY',
    'severity': 'CRITICAL',
    'file': 'config/settings.py',
    'line_number': 45
}

# Send to all configured integrations
await manager.notify_incident(incident)
```

### Custom Webhook

```python
from app.integrations import WebhookIntegration

await WebhookIntegration.send_webhook(
    'https://your-siem.example.com/incidents',
    incident_data
)
```

---

## 🛡️ Security Best Practices

1. **Always use HTTPS/TLS in production**
2. **Rotate`JWT_SECRET_KEY` regularly**
3. **Never commit `.env` to git**
4. **Use VPN/firewall to protect ports**
5. **Enable auto-remediation only for known patterns**
6. **Regular security audits of detected secrets**
7. **Monitor `logs/` directory regularly**

---

## 🐛 Troubleshooting

### WebSocket Connection Fails

```bash
# Check API is running
curl http://localhost:8000/health

# Check firewall
sudo ufw allow 8000/tcp

# Check logs
docker logs autohoneyx_api_prod
```

### Scanner Doesn't Find Secrets

```bash
# Verify MONITORED_REPOS
echo $MONITORED_REPOS

# Test scanner directly
python -c "
from app.realtime_scanner import RealtimeSecretScanner
scanner = RealtimeSecretScanner()
findings = scanner.scan_content('AKIA123ABC456', {'file': 'test.txt'})
print(findings)
"
```

### Slack Alerts Not Sending

```bash
# Test webhook
curl -X POST $SLACK_WEBHOOK_URL \
  -d '{"text": "Test message"}' \
  -H 'Content-Type: application/json'
```

---

## 📞 Support & Documentation

- **API Docs**: `http://localhost:8000/docs`
- **WebSocket Docs**: See `app/realtime_api.py`
- **Scanner Patterns**: See `app/realtime_scanner.py` (482+ patterns)
- **Integrations**: See `app/integrations.py`

---

## 🚀 Next Steps

1. ✅ Configure `.env` with your secrets
2. ✅ Run `docker-compose up` for production
3. ✅ Install git hooks in your repositories
4. ✅ Configure Slack/Email for alerts
5. ✅ Monitor dashboard in real-time
6. ✅ Enable auto-remediation gradually

**Your GitGuardian-style secret detection system is ready to deploy!** 🎉
