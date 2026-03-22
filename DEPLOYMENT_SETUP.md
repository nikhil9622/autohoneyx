# 🚀 AutoHoneyX DigitalOcean Deployment Guide

## **STEP 1: GitHub Setup (5 minutes)**

### 1.1 Create GitHub Repository

```powershell
# Open browser and go to:
# https://github.com/new

# Fill in:
# Repository name: AutoHoneyX
# Description: Intelligent Honeytoken & Honeypot Management System
# Public: Yes (for easy access)
# Click "Create repository"

# You'll get: https://github.com/nikhil9622/AutoHoneyX
```

### 1.2 Push Code to GitHub

**Run these commands in PowerShell** (in your AutoHoneyX folder):

```powershell
cd C:\Users\bhave\Downloads\AutoHoneyX

# Initialize git (if not already done)
git init

# Configure git
git config user.email "nikhil@example.com"
git config user.name "nikhil9622"

# Add all files
git add .

# Create commit
git commit -m "Initial AutoHoneyX deployment - Ready for DigitalOcean"

# Add remote (replace with your URL)
git remote add origin https://github.com/nikhil9622/AutoHoneyX.git

# Push to GitHub
git branch -M main
git push -u origin main
```

**If GitHub asks for password:**
1. Go to: https://github.com/settings/tokens/new
2. Check: ✅ `repo` (full control)
3. Generate token
4. Use token as password when prompted

**Verify:** Go to https://github.com/nikhil9622/AutoHoneyX - should see all files ✅

---

## **STEP 2: DigitalOcean Setup (10 minutes)**

### 2.1 Create DigitalOcean Account

```
1. Go to: https://www.digitalocean.com/
2. Sign up (use friend's account for credits)
3. Verify email
4. Add your GitHub repo as connected account
```

### 2.2 Create API Token

**In DigitalOcean Dashboard:**

```
1. Click your profile (top right) → Settings → API
2. Click "Tokens/Keys" → Personal Access Tokens
3. Click "Generate New Token"
4. Name: autohoneyx-github-deploy
5. Scopes: ✅ read, ✅ write
6. Click "Generate Token"
7. COPY THE TOKEN (looks like: dop_v1_abc123...)
8. Save it in a safe place
```

### 2.3 Add Token to GitHub Secrets

**In GitHub:**

```
1. Go to: https://github.com/nikhil9622/AutoHoneyX
2. Click: Settings → Secrets and variables → Actions
3. Click: "New repository secret"
4. Name: DIGITALOCEAN_ACCESS_TOKEN
5. Value: [Paste your DO token from above]
6. Click "Add secret"
```

---

## **STEP 3: Deploy (5 minutes)**

### 3.1 Automatic Deployment via GitHub Actions

The deployment automatically starts when you **push to GitHub**.

**Check deployment status:**

```
1. Go to: https://github.com/nikhil9622/AutoHoneyX/actions
2. Look for "Deploy to DigitalOcean" workflow
3. Click on it to see status
```

**If deployment fails:**
- Check the workflow logs for errors
- Common issues:
  - Missing API token in secrets
  - Dockerfile syntax errors
  - Insufficient DigitalOcean credits

### 3.2 Manual Deployment (Alternative)

If GitHub Actions doesn't work, deploy manually:

```powershell
# 1. Create a Droplet
#    DigitalOcean Dashboard → Create → Droplet
#    - Ubuntu 22.04 x64
#    - $6/month Basic
#    - Copy SSH key when prompted
#    - Name: autohoneyx-prod

# 2. Once droplet is created, SSH into it:
ssh -i C:\path\to\ssh\key root@your-droplet-ip

# 3. On the droplet, run:
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 4. Clone your repo
sudo git clone https://github.com/nikhil9622/AutoHoneyX.git /opt/autohoneyx
cd /opt/autohoneyx/AutoHoneyX

# 5. Create .env file
sudo nano .env

# Add:
DATABASE_URL=postgresql://autohoneyx:secure_password@postgres:5432/autohoneyx_db
JWT_SECRET_KEY=your-random-secret-key-min-32-chars
ENVIRONMENT=production
ALLOWED_ORIGINS=http://your-droplet-ip:8501,http://your-droplet-ip:8000

# 6. Start services
sudo docker-compose -f docker-compose.prod.yml up -d

# 7. Check status
sudo docker-compose ps
```

---

## **STEP 4: Access Your Deployment**

**Once deployed, access at:**

```
API Docs:  http://your-droplet-ip:8000/docs
Dashboard: http://your-droplet-ip:8501
API:       http://your-droplet-ip:8000
```

**To find your Droplet IP:**
1. DigitalOcean Dashboard → Droplets
2. Click your droplet → Copy IP address

---

## **STEP 5: Testing (10 minutes)**

### 5.1 Test API

```bash
# In your browser or Postman:

# 1. Generate Token
POST http://your-droplet-ip:8000/api/tokens/generate
Body:
{
  "token_type": "aws",
  "count": 3
}

# 2. Check IP Reputation
POST http://your-droplet-ip:8000/api/threat-intel/check-ip
Body:
{
  "ip_address": "1.1.1.1"
}

# 3. Detect Evasion
POST http://your-droplet-ip:8000/api/honeypot/detect-evasion
Body:
{
  "user_input": "whoami; docker ps; nmap",
  "user_agent": "curl/7.64.1"
}
```

### 5.2 Test Dashboard

```
1. Go to: http://your-droplet-ip:8501
2. Should see Streamlit dashboard loading
3. Create a test honeytoken
4. View attack logs
```

---

## **STEP 6: Shutdown (After 2 Days)**

### 6.1 Delete Everything

```powershell
# Option A: Delete via DigitalOcean Dashboard (Fastest)
# 1. Go to DigitalOcean Dashboard
# 2. Click Droplet
# 3. Click "More" → "Destroy"
# 4. Confirm deletion
# Result: $0 charges, everything deleted

# Option B: Keep Droplet but Stop (for later use)
# 1. SSH into droplet
# 2. Stop services:
sudo docker-compose -f docker-compose.prod.yml down

# 3. Remove volumes:
sudo docker volume prune -f

# 4. In Dashboard: Click Droplet → "Power Off"
# Result: ~$0.01/day storage charge only
```

---

## **Cost Summary**

```
For 2 days:
- Droplet ($6/month):     ~$0.40
- PostgreSQL ($13/month): ~$0.87
- Redis ($6/month):       ~$0.40
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total: ~$1.67 ✅

Friend's credits: ~$100
Remaining: ~$98.33 ✅
```

---

## **Environment Variables Explained**

| Variable | Example | Purpose |
|----------|---------|---------|
| `JWT_SECRET_KEY` | Random 32+ chars | API authentication |
| `DATABASE_URL` | postgres://user:pass@host/db | PostgreSQL connection |
| `ENVIRONMENT` | production | App mode (dev/prod) |
| `SLACK_WEBHOOK_URL` | https://hooks.slack.com/... | Slack alerts |
| `GITHUB_TOKEN` | ghp_... | GitHub integration |
| `REDIS_URL` | redis://host:6379 | Redis cache |

---

## **Troubleshooting**

### **"Docker not found"**
```powershell
# Install Docker Desktop
# https://www.docker.com/products/docker-desktop
# Or via scoop:
scoop install docker
```

### **"Git not found"**
```powershell
scoop install git
```

### **"Permission denied" on DigitalOcean**
```bash
# Run commands with sudo
sudo docker-compose ps
```

### **Port 8501/8000 already in use**
```powershell
# Find process using port
netstat -ano | findstr :8501

# Kill process (replace PID)
taskkill /PID <PID> /F
```

---

## **Success Checklist**

- [ ] GitHub repo created
- [ ] Code pushed to GitHub
- [ ] DigitalOcean account ready
- [ ] API token created and added to GitHub Secrets
- [ ] GitHub Actions workflow triggered
- [ ] Droplet deployed successfully
- [ ] Can access Dashboard at http://droplet-ip:8501
- [ ] Can access API at http://droplet-ip:8000/docs
- [ ] Generate token test works
- [ ] Ready for demo!

---

**Questions? Stuck somewhere? Let me know!** 🚀
