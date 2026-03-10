"""Initialize database schema"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import init_db, engine
from app.models import Base

def main():
    """Initialize database"""
    print("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        print("[OK] Database schema created successfully")
    except Exception as e:
        print(f"[ERROR] Error creating database schema: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

