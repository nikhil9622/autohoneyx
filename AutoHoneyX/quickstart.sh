#!/bin/bash
# ============================================================================
# AutoHoneyX Real-Time Secret Detection System - Quick Start
# GitGuardian-Style Implementation
# ============================================================================

set -e

echo "🔒 AutoHoneyX Real-Time Setup"
echo "================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python 3 found${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker not found - will run in development mode${NC}"
    USE_DOCKER=false
else
    echo -e "${GREEN}✅ Docker found${NC}"
    USE_DOCKER=true
fi

# Setup environment
echo ""
echo "📝 Setting up environment..."

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✅ Created .env (please edit with your settings)${NC}"
else
    echo -e "${YELLOW}⚠️  .env already exists${NC}"
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -q -r requirements.txt 2>/dev/null && echo -e "${GREEN}✅ Dependencies installed${NC}" || echo -e "${RED}❌ Failed to install dependencies${NC}"

# Create directories
mkdir -p logs monitoring

# Database setup
echo ""
echo "🗄️  Initializing database..."
python3 -c "
from app.database import Base, engine
from app.models import Honeytoken, AttackLog, Alert
Base.metadata.create_all(bind=engine)
print('✅ Database tables created')
" 2>/dev/null || true

# Git hooks
echo ""
echo "🔧 Installing Git hooks..."
python3 -c "
from app.git_hooks import install_all_hooks
try:
    install_all_hooks('.')
    print('✅ Git pre-commit hook installed')
except:
    print('⚠️  Could not install git hooks (optional)')
" 2>/dev/null || true

echo ""
echo ""
echo "🎯 Setup Complete!"
echo ""
echo "================================"
echo "📌 Next Steps:"
echo "================================"
echo ""
echo "1️⃣  Edit .env with your configuration:"
echo "   nano .env"
echo ""
echo "2️⃣  Start the system:"
echo ""

if [ "$USE_DOCKER" = true ]; then
    echo "   Option A (Docker - Recommended):"
    echo "   docker-compose -f docker-compose.prod.yml up -d"
    echo ""
fi

echo "   Option B (Development):"
echo "   Terminal 1: python -m uvicorn app.realtime_api:app --reload"
echo "   Terminal 2: python -m monitoring.monitor_service"
echo "   Terminal 3: streamlit run dashboard/app.py"
echo ""
echo "3️⃣  Access the system:"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Dashboard: http://localhost:8501"
echo "   Prometheus: http://localhost:9090"
echo "   Grafana: http://localhost:3000"
echo ""
echo "4️⃣  Configure alerts:"
echo "   - Slack: Add SLACK_WEBHOOK_URL to .env"
echo "   - Email: Add SMTP settings to .env"
echo "   - GitHub: Add GITHUB_TOKEN for repo scanning"
echo ""
echo "================================"
echo "🔒 Security Monitoring is Ready!"
echo "================================"
