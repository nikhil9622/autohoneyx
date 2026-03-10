# AutoHoneyX Test Projects

This directory contains sample projects designed to test AutoHoneyX honeytoken injection functionality. Each project contains realistic credential patterns that serve as perfect targets for honeytoken injection.

## 📁 Project Structure

### 1. `python-flask-app/` - Python Flask Web Application
- **Framework**: Flask 2.3.3
- **Injection Targets**:
  - AWS credentials in `config/settings.py`
  - Database credentials in configuration
  - API keys for various services
  - SSH private keys
- **Best for**: Testing Python code injection

### 2. `nodejs-api/` - Node.js Express API
- **Framework**: Express.js + AWS SDK
- **Injection Targets**:
  - AWS credentials in `.env`
  - Database configuration
  - API keys and tokens
  - SSH configuration
- **Best for**: Testing JavaScript/TypeScript injection

### 3. `config-files-example/` - Configuration Files
- **Files**: YAML, JSON configuration files
- **Injection Targets**:
  - Database credentials
  - AWS access keys
  - API keys and secrets
  - SSH keys and certificates
- **Best for**: Testing configuration file injection

### 4. `python-scripts/` - Python Utility Scripts
- **Type**: Deployment and utility scripts
- **Injection Targets**:
  - AWS credentials in code
  - Database passwords
  - API tokens and webhooks
  - SSH private keys
- **Best for**: Testing script-based injection

## 🧪 How to Test with AutoHoneyX

### Step 1: Start AutoHoneyX Dashboard
```powershell
cd C:\Users\Amma\Desktop\AutoHoneyX
.\start.ps1
```
Access dashboard at: `http://localhost:8501`

### Step 2: Generate Honeytokens
1. Open dashboard → "Honeytokens" tab → "Generate New"
2. Create tokens for different types:
   - AWS credentials
   - Database credentials
   - API keys
   - SSH keys

### Step 3: Inject Honeytokens
1. Go to "Honeytokens" → "Injection" tab
2. Select target project directory (e.g., `python-flask-app`)
3. Choose token types and injection count
4. Click "Inject Tokens"

### Step 4: Verify Injection
1. Check the project files for injected honeytokens
2. Look for comments like:
   ```python
   # HONEYTTOKEN: AWS_ACCESS_KEY_ID=AKIA...
   AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
   ```

### Step 5: Test Honeypot Detection
1. Use the fake credentials from injected tokens
2. Try to connect to honeypots:
   ```bash
   # SSH Honeypot
   ssh -p 2222 fakeuser@localhost

   # Web Honeypot
   curl http://localhost:8080/admin

   # Database Honeypot
   mysql -h localhost -P 3307 -u fakeuser -p
   ```

### Step 6: Monitor Results
1. Check dashboard for triggered alerts
2. View attack logs and behavior analysis
3. Verify honeytoken detection

## 🎯 Expected Results

After successful injection and testing, you should see:

1. **Injected Tokens**: Fake credentials in project files
2. **Attack Detection**: Logs when fake credentials are used
3. **Alerts**: Email/Slack notifications for security events
4. **Behavioral Analysis**: ML classification of attack patterns
5. **Dashboard Updates**: Real-time statistics and visualizations

## 🔧 Configuration

Each project includes realistic but **FAKE** credentials designed for testing:

- **AWS Keys**: `AKIAIOSFODNN7EXAMPLE` format
- **Database Passwords**: `mypassword123`, `super_secret_password_2024!`
- **API Keys**: `sk-1234567890abcdef` format
- **SSH Keys**: Sample private key format

## ⚠️ Security Notice

These test projects contain **intentionally fake** credentials for testing purposes only. They should never be used in production environments.

## 📊 Test Coverage

This test suite covers:
- ✅ Multiple programming languages (Python, JavaScript)
- ✅ Various credential types (AWS, DB, API, SSH)
- ✅ Different file formats (code, config files, scripts)
- ✅ Realistic application architectures
- ✅ Common security patterns and anti-patterns