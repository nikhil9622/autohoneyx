from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def index():
    return 'AutoHoneyX DB Honeypot (placeholder)\n', 200

if __name__ == '__main__':
    port = int(os.getenv('DB_PORT', 3307))
    app.run(host='0.0.0.0', port=port)
