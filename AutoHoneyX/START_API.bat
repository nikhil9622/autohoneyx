@echo off
REM AutoHoneyX Startup Script for Windows

cd /d "%~dp0"

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Set environment variables  
set DATABASE_URL=sqlite:///autohoneyx_dev.db
set ENVIRONMENT=development
set LOG_LEVEL=INFO
set PYTHONPATH=%cd%

REM Initialize database if needed
echo Checking database...
python run.py init-db

REM Start API server
echo.
echo Starting FastAPI Server on http://127.0.0.1:8000
echo API Documentation: http://127.0.0.1:8000/docs
echo.

python -m uvicorn app.realtime_api:app --host 127.0.0.1 --port 8000 --reload

pause
