#!/usr/bin/env python3
"""Start the AutoHoneyX API Server"""

import os
import sys
import subprocess

# Set environment variables
os.environ['ENVIRONMENT'] = 'development'
os.environ['DATABASE_URL'] = 'sqlite:///autohoneyx_dev.db'

# Get the venv python executable
venv_python = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'python.exe'))

# Run uvicorn with the venv python
cmd = [
    venv_python,
    '-m', 'uvicorn',
    'app.realtime_api:app',
    '--host', '127.0.0.1',
    '--port', '8000',
    '--reload'
]

print(f"Starting API Server...")
print(f"♦ Endpoint: http://127.0.0.1:8000")
print(f"♦ API Docs: http://127.0.0.1:8000/docs")
print(f"♦ ReDocs: http://127.0.0.1:8000/redoc")
print()

# Change to the project directory
os.chdir(os.path.dirname(__file__))

# Execute the command
subprocess.run(cmd)
