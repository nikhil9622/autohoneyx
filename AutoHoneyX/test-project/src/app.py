"""Main application file for the test project"""

import os
import sys
from utils.database import DatabaseConnection
from utils.logger import Logger
from models.user import User
from api.auth import AuthService

class Application:
    """Main application class"""

    def __init__(self):
        self.db = DatabaseConnection()
        self.logger = Logger()
        self.auth_service = AuthService()

    def initialize(self):
        """Initialize the application"""
        print("Initializing application...")

        # Connect to database
        if self.db.connect():
            self.logger.info("Database connected successfully")
        else:
            self.logger.error("Failed to connect to database")

        # Setup authentication
        self.auth_service.setup()

        return True

    def run(self):
        """Run the main application loop"""
        self.logger.info("Application started")

        while True:
            try:
                # Main application logic would go here
                command = input("Enter command (or 'quit' to exit): ")

                if command.lower() == 'quit':
                    break
                elif command.lower() == 'users':
                    self.show_users()
                else:
                    print("Unknown command")

            except KeyboardInterrupt:
                print("\nShutting down...")
                break
            except Exception as e:
                self.logger.error(f"Error: {e}")

    def show_users(self):
        """Display all users"""
        users = self.db.get_all_users()
        for user in users:
            print(f"User: {user.name} - {user.email}")

if __name__ == "__main__":
    app = Application()
    if app.initialize():
        app.run()

