"""Database connection utilities"""

import sqlite3
from typing import List, Optional
from config.settings import DATABASE_URL

class DatabaseConnection:
    """Handles database connections and operations"""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or DATABASE_URL
        self.connection = None

    def connect(self) -> bool:
        """Establish database connection"""
        try:
            self.connection = sqlite3.connect(self.db_url)
            print(f"Connected to database: {self.db_url}")
            return True
        except Exception as e:
            print(f"Database connection failed: {e}")
            return False

    def execute_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute a database query"""
        if not self.connection:
            raise Exception("No database connection")

        cursor = self.connection.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def get_all_users(self) -> List[dict]:
        """Get all users from database"""
        query = "SELECT id, name, email FROM users"
        results = self.execute_query(query)

        users = []
        for row in results:
            users.append({
                'id': row[0],
                'name': row[1],
                'email': row[2]
            })
        return users

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("Database connection closed")

