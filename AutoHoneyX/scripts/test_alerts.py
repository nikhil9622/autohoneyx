"""Test alerting system"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from monitoring.alerting import AlertManager
from app.models import Alert

def main():
    print("Testing alert system...")
    
    alert_manager = AlertManager()
    
    # Create test alert
    alert = alert_manager.create_alert(
        alert_type='test',
        severity='HIGH',
        title='Test Alert',
        message='This is a test alert to verify the alerting system is working correctly.',
        alert_metadata={'test': True}
    )
    
    print(f"Created test alert: {alert.id}")
    
    # Try to send alert
    print("Sending alert via email...")
    email_sent = alert_manager.send_email_alert(alert)
    
    print("Sending alert via Slack...")
    slack_sent = alert_manager.send_slack_alert(alert)
    
    if email_sent or slack_sent:
        print("✓ Alert system is working!")
    else:
        print("⚠ Alert system configured but no channels sent (check configuration)")

if __name__ == "__main__":
    main()

