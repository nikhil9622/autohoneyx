from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    return 'AutoHoneyX Web Honeypot (placeholder)\n', 200

@app.route('/admin')
def admin():
    return 'Admin panel (honeypot placeholder)', 200

if __name__ == '__main__':
    port = int(os.getenv('WEB_PORT', 8080))
    app.run(host='0.0.0.0', port=port)
