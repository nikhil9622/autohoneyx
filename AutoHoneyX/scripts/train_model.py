"""Script to train behavioral analysis model"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import get_db_session
from app.models import AttackLog
from monitoring.behavior_analyzer import BehaviorAnalyzer

def main():
    print("Training behavioral analysis model...")
    
    # Get recent attack logs
    with get_db_session() as db:
        attack_logs = db.query(AttackLog).filter(
            AttackLog.timestamp >= datetime.utcnow() - timedelta(days=90)
        ).all()
    
    print(f"Found {len(attack_logs)} attack logs for training")
    
    if len(attack_logs) < 10:
        print("Warning: Need at least 10 attack logs for training. Using synthetic data...")
        # In production, you'd want to add synthetic data generation
    
    analyzer = BehaviorAnalyzer()
    analyzer.train_model(attack_logs)
    
    print("✓ Model training complete!")

if __name__ == "__main__":
    main()

