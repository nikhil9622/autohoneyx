# ============================================================================
# AutoHoneyX Real-Time Secret Detection System - Quick Start (Windows)
# GitGuardian-Style Implementation
# ============================================================================

Write-Host "🔒 AutoHoneyX Real-Time Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ $pythonVersion found" -ForegroundColor Green
} catch {
    Write-Host "❌ Python 3 is required (https://python.org)" -ForegroundColor Red
    exit 1
}

# Check Docker
Write-Host "Checking Docker installation..." -ForegroundColor Yellow
$useDocker = $false
try {
    docker --version | Out-Null
    $dockerVersion = docker --version
    Write-Host "✅ $dockerVersion found" -ForegroundColor Green
    $useDocker = $true
} catch {
    Write-Host "⚠️  Docker not found - will run in development mode" -ForegroundColor Yellow
}

Write-Host ""

# Setup environment
Write-Host "📝 Setting up environment..." -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "✅ Created .env (please edit with your settings)" -ForegroundColor Green
} else {
    Write-Host "⚠️  .env already exists" -ForegroundColor Yellow
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
python -m pip install -q -r requirements.txt 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
}

# Create directories
Write-Host "📁 Creating directories..." -ForegroundColor Cyan
@("logs", "monitoring") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ | Out-Null
    }
}
Write-Host "✅ Directories created" -ForegroundColor Green

# Database setup
Write-Host ""
Write-Host "🗄️  Initializing database..." -ForegroundColor Cyan
python -c @"
try:
    from app.database import Base, engine
    from app.models import Honeytoken, AttackLog, Alert
    Base.metadata.create_all(bind=engine)
    print('✅ Database tables created')
except Exception as e:
    print(f'⚠️  Database already initialized: {e}')
"@ 2>$null

# Git hooks
Write-Host ""
Write-Host "🔧 Installing Git hooks (optional)..." -ForegroundColor Cyan
python -c @"
try:
    from app.git_hooks import install_all_hooks
    install_all_hooks('.')
    print('✅ Git pre-commit hook installed')
except Exception as e:
    print(f'⚠️  Could not install git hooks: {e}')
"@ 2>$null

Write-Host ""
Write-Host ""
Write-Host "🎯 Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "📌 Next Steps:" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1️⃣  Edit .env with your configuration:" -ForegroundColor White
Write-Host "   notepad .env" -ForegroundColor Gray
Write-Host ""
Write-Host "2️⃣  Start the system:" -ForegroundColor White

if ($useDocker) {
    Write-Host ""
    Write-Host "   Option A (Docker - Recommended):" -ForegroundColor White
    Write-Host "   docker-compose -f docker-compose.prod.yml up -d" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "   Option B (Development Mode):" -ForegroundColor White
Write-Host ""
Write-Host "   PowerShell Terminal 1 (Real-Time API):" -ForegroundColor Gray
Write-Host "   python -m uvicorn app.realtime_api:app --reload --port 8000" -ForegroundColor Gray
Write-Host ""
Write-Host "   PowerShell Terminal 2 (Monitoring Service):" -ForegroundColor Gray
Write-Host "   python -m monitoring.monitor_service" -ForegroundColor Gray
Write-Host ""
Write-Host "   PowerShell Terminal 3 (Dashboard):" -ForegroundColor Gray
Write-Host "   streamlit run dashboard/app.py" -ForegroundColor Gray
Write-Host ""
Write-Host "3️⃣  Access the system:" -ForegroundColor White
Write-Host "   📊 API Docs:        http://localhost:8000/docs" -ForegroundColor Gray
Write-Host "   🎨 Dashboard:       http://localhost:8501" -ForegroundColor Gray
Write-Host "   📈 Prometheus:      http://localhost:9090" -ForegroundColor Gray
Write-Host "   📊 Grafana:         http://localhost:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "4️⃣  Configure alerts:" -ForegroundColor White
Write-Host "   - Slack: Add SLACK_WEBHOOK_URL to .env" -ForegroundColor Gray
Write-Host "   - Email: Add SMTP settings to .env" -ForegroundColor Gray
Write-Host "   - GitHub: Add GITHUB_TOKEN for repo scanning" -ForegroundColor Gray
Write-Host ""
Write-Host "5️⃣  Useful commands:" -ForegroundColor White
Write-Host "   Build Docker image: docker build -t autohoneyx:latest -f Dockerfile.prod ." -ForegroundColor Gray
Write-Host "   View logs:          docker logs autohoneyx_api_prod" -ForegroundColor Gray
Write-Host "   Stop services:      docker-compose -f docker-compose.prod.yml down" -ForegroundColor Gray
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "🔒 Security Monitoring is Ready!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Offer to open .env
$openEnv = Read-Host "Open .env file now? (Y/n)"
if ($openEnv -ne "n" -and $openEnv -ne "N") {
    notepad .env
}

Write-Host ""
Write-Host "For more information, see:" -ForegroundColor Cyan
Write-Host "  - REALTIME_DEPLOYMENT_GUIDE.md" -ForegroundColor Gray
Write-Host "  - REALTIME_FEATURES.md" -ForegroundColor Gray
Write-Host "  - README.md" -ForegroundColor Gray
