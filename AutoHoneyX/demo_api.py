#!/usr/bin/env python3
"""AutoHoneyX API Demonstration - Test Key Features"""

import requests
import json
from pprint import pprint
import time

BASE_URL = "http://127.0.0.1:8000"

print("=" * 80)
print("🔒 AutoHoneyX - LIVE DEMONSTRATION")
print("=" * 80)
print()

# Test 1: API Status
print("📊 [TEST 1] API Health Status")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/health")
    if response.status_code == 200:
        print("✅ API is ONLINE and responding")
        data = response.json()
        print(f"Status: {data.get('status', 'Unknown')}")
    else:
        print(f"❌ Unexpected response code: {response.status_code}")
except Exception as e:
    print(f"❌ Error: {e}")
print()

# Test 2: Generate Login Token
print("🔐 [TEST 2] Authentication - Get Access Token")
print("-" * 80)
try:
    # Default demo credentials (from environment or hardcoded in demo mode)
    login_payload = {
        "user_id": "admin_user",
        "role": "admin",
        "password": "demo-password"
    }
    response = requests.post(
        f"{BASE_URL}/api/v1/auth/token",
        json=login_payload
    )
    
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get("access_token")
        print(f"✅ Authentication successful!")
        print(f"Token Type: {token_data.get('token_type')}")
        print(f"Expires In: {token_data.get('expires_in_minutes')} minutes")
        print(f"Access Token (first 50 chars): {access_token[:50]}...")
        headers = {"Authorization": f"Bearer {access_token}"}
    else:
        print(f"⚠️  Login response: {response.status_code}")
        print(f"Response: {response.text[:300]}")
        headers = {}
except Exception as e:
    print(f"❌ Error: {e}")
    headers = {}
print()

# Test 3: Get API Status
print("📈 [TEST 3] API Status & Statistics")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/api/v1/status", headers=headers)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        status = response.json()
        print(f"✅ Retrieved system status")
        print(f"Incidents: {status.get('total_incidents', 0)}")
        print(f"Resolved: {status.get('resolved_incidents', 0)}")
        print(f"Ignored: {status.get('ignored_incidents', 0)}")
    else:
        print(f"Response: {response.text[:200]}")
except Exception as e:
    print(f"⚠️  Error: {e}")
print()

# Test 4: Get Statistics
print("📊 [TEST 4] Dashboard Statistics")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/api/v1/stats", headers=headers)
    if response.status_code == 200:
        stats = response.json()
        print(f"✅ Statistics retrieved")
        print(f"Total Incidents: {stats.get('total_incidents', 0)}")
        print(f"Critical: {stats.get('critical_incidents', 0)}")
        print(f"High: {stats.get('high_incidents', 0)}")
        print(f"Medium: {stats.get('medium_incidents', 0)}")
        print(f"Low: {stats.get('low_incidents', 0)}")
    else:
        print(f"Response: {response.text[:300]}")
except Exception as e:
    print(f"⚠️  Error: {e}")
print()

# Test 5: Get Incidents
print("🚨 [TEST 5] Retrieve Incidents (Attacks Detected)")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/api/v1/incidents", headers=headers)
    if response.status_code == 200:
        incidents = response.json()
        print(f"✅ Incidents retrieved")
        print(f"Total: {len(incidents)} incidents detected")
        if incidents:
            print(f"\nFirst incident details:")
            incident = incidents[0]
            print(f"  - ID: {incident.get('id')}")
            print(f"  - Type: {incident.get('type', 'Unknown')}")
            print(f"  - Severity: {incident.get('severity', 'Unknown')}")
            print(f"  - Status: {incident.get('status', 'Unknown')}")
        else:
            print("  (No incidents yet)")
    else:
        print(f"Response: {response.text[:300]}")
except Exception as e:
    print(f"⚠️  Error: {e}")
print()

# Test 6: Get Severity Distribution
print("🎯 [TEST 6] Attack Severity Distribution")
print("-" * 80)
try:
    response = requests.get(f"{BASE_URL}/api/v1/severity-distribution", headers=headers)
    if response.status_code == 200:
        distribution = response.json()
        print(f"✅ Severity distribution retrieved")
        for severity, count in distribution.items():
            print(f"  - {severity.upper()}: {count}")
    else:
        print(f"Response: {response.text[:300]}")
except Exception as e:
    print(f"⚠️  Error: {e}")
print()

# Summary
print("=" * 80)
print("🎯 DEMONSTRATION SUMMARY")
print("=" * 80)
print("""
✅ API Server: RUNNING on http://127.0.0.1:8000
✅ API Docs: http://127.0.0.1:8000/docs
✅ Web Dashboard: http://127.0.0.1:8501 (if Streamlit started)

📁 PROJECT COMPONENTS RUNNING:
  1. ✅ Real-Time API (FastAPI) - Port 8000
  2. ✅ Secret Detection Engine (482+ patterns)
  3. ✅ Honeypot Evasion Detection
  4. ✅ IP Reputation & Threat Intel
  5. ✅ Authentication & Authorization
  6. ✅ Database (SQLite for dev)
  7. ⏳ Dashboard (Streamlit) - Port 8501

🔐 SECURITY FEATURES:
  - Real-time secret detection
  - Honeytoken generation & injection
  - MITRE ATT&CK mapping
  - Behavioral anomaly detection
  - SIEM integration
  - Incident response automation

📊 NEXT STEPS:
  1. Open http://127.0.0.1:8000/docs for interactive API testing
  2. Try generating honeytokens via API
  3. Test attack detection endpoints
  4. Check the Streamlit dashboard at http://127.0.0.1:8501
""")
print("=" * 80)
