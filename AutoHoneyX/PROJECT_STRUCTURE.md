# AutoHoneyX Project Structure

## Directory Overview

```
AutoHoneyX/
├── app/                          # Core application code
│   ├── __init__.py
│   ├── config.py                # Configuration management
│   ├── database.py              # Database connection & session management
│   ├── models.py                # SQLAlchemy database models
│   ├── honeytoken_generator.py  # Honeytoken generation logic
│   └── injection_engine.py      # Code injection engine
│
├── honeypots/                    # Honeypot implementations
│   ├── __init__.py
│   ├── ssh/                     # SSH honeypot
│   │   ├── __init__.py
│   │   ├── app.py              # SSH honeypot server
│   │   └── Dockerfile          # Docker configuration
│   ├── web/                     # Web honeypot
│   │   ├── __init__.py
│   │   ├── app.py              # Flask web honeypot
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── database/                # Database honeypot
│       ├── __init__.py
│       ├── app.py              # Database honeypot server
│       ├── Dockerfile
│       └── requirements.txt
│
├── monitoring/                   # Monitoring and alerting
│   ├── __init__.py
│   ├── monitor_service.py      # Main monitoring service
│   ├── alerting.py             # Alert management and sending
│   └── behavior_analyzer.py    # ML-based behavioral analysis
│
├── dashboard/                    # Streamlit dashboard
│   ├── __init__.py
│   └── app.py                  # Main dashboard application
│
├── scripts/                      # Utility scripts
│   ├── __init__.py
│   ├── init_db.py              # Initialize database schema
│   ├── generate_tokens.py      # Generate honeytokens CLI
│   ├── inject_tokens.py        # Inject tokens CLI
│   ├── train_model.py          # Train ML model
│   └── test_alerts.py          # Test alert system
│
├── tests/                        # Test suite
│   ├── __init__.py
│   └── test_honeytoken_generator.py
│
├── .github/                      # GitHub workflows
│   └── workflows/
│       └── ci.yml              # CI/CD pipeline
│
├── logs/                         # Log files directory
├── models/                       # ML model files
├── honeypot_data/               # Honeypot data storage
│
├── docker-compose.yml           # Docker orchestration
├── Dockerfile                   # Main application container
├── init.sql                     # Database initialization script
├── requirements.txt             # Python dependencies
├── pytest.ini                   # Pytest configuration
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
│
├── README.md                    # Main documentation
├── DEPLOYMENT.md               # Deployment guide
├── QUICKSTART.md               # Quick start guide
├── PROJECT_STRUCTURE.md        # This file
└── LICENSE                     # MIT License
```

## Key Components

### 1. Core Application (`app/`)
- **config.py**: Manages all configuration from environment variables
- **database.py**: Database connection pooling and session management
- **models.py**: SQLAlchemy ORM models (Honeytoken, AttackLog, Alert, BehaviorAnalysis)
- **honeytoken_generator.py**: Generates realistic fake credentials
- **injection_engine.py**: Injects honeytokens into code files

### 2. Honeypots (`honeypots/`)
Each honeypot type has its own directory with:
- **app.py**: Honeypot server implementation
- **Dockerfile**: Container configuration
- **requirements.txt**: Python dependencies (if needed)

### 3. Monitoring (`monitoring/`)
- **monitor_service.py**: Main service that monitors all components
- **alerting.py**: Email and Slack alert management
- **behavior_analyzer.py**: Machine learning model for attack classification

### 4. Dashboard (`dashboard/`)
- **app.py**: Streamlit web application with multiple pages

### 5. Scripts (`scripts/`)
Utility scripts for common operations:
- Database initialization
- Token generation
- Token injection
- Model training
- Alert testing

## Data Flow

```
1. Honeytoken Generation
   scripts/generate_tokens.py → app/honeytoken_generator.py → Database

2. Token Injection
   scripts/inject_tokens.py → app/injection_engine.py → Code Files → Database

3. Attack Detection
   Honeypots → Log Events → Database (AttackLog)

4. Monitoring
   monitoring/monitor_service.py → Check Database → Trigger Alerts

5. Analysis
   monitoring/behavior_analyzer.py → Analyze Attacks → Store Results

6. Visualization
   dashboard/app.py → Query Database → Display Results
```

## Database Schema

### Tables
- **honeytokens**: Stores all generated honeytokens
- **attack_logs**: Stores all attack events from honeypots
- **alerts**: Stores all security alerts
- **behavior_analysis**: Stores ML analysis results

## Docker Services

1. **postgres**: PostgreSQL database
2. **app**: Streamlit dashboard
3. **ssh_honeypot**: SSH honeypot container
4. **web_honeypot**: Web honeypot container
5. **db_honeypot**: Database honeypot container
6. **monitor**: Monitoring service container

## Environment Variables

See `.env.example` for all configuration options. Key variables:
- Database connection settings
- Email/Slack alert configuration
- Honeypot port numbers
- Application settings

## Development Workflow

1. **Local Development**
   ```bash
   docker-compose up -d
   docker-compose exec app python scripts/init_db.py
   ```

2. **Code Changes**
   - Edit code in respective directories
   - Changes reflected immediately (volume mounts)

3. **Testing**
   ```bash
   pytest tests/
   ```

4. **Deployment**
   - Push to GitHub
   - CI/CD pipeline runs tests
   - Deploys to cloud server

## File Naming Conventions

- **Python files**: snake_case (e.g., `honeytoken_generator.py`)
- **Classes**: PascalCase (e.g., `HoneytokenGenerator`)
- **Functions/Methods**: snake_case (e.g., `generate_aws_key`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `DATABASE_URL`)

## Adding New Features

### New Honeypot Type
1. Create directory in `honeypots/`
2. Implement honeypot server in `app.py`
3. Add Dockerfile
4. Add service to `docker-compose.yml`

### New Token Type
1. Add generation method to `app/honeytoken_generator.py`
2. Update injection logic in `app/injection_engine.py`
3. Add tests in `tests/`

### New Dashboard Page
1. Add page function to `dashboard/app.py`
2. Add navigation option in sidebar
3. Implement page UI and database queries

