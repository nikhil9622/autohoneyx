import socket
import os

HOST = '0.0.0.0'
PORT = int(os.getenv('COWRIE_SSH_PORT', os.getenv('SSH_HONEYPOT_PORT', 2222)))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"SSH honeypot placeholder listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        with conn:
            print('Connection from', addr)
            try:
                conn.sendall(b'Welcome to AutoHoneyX SSH honeypot\n')
            except Exception:
                pass
