import json
import os
import socket
import threading
import time
from datetime import datetime

import paramiko


HOST = "0.0.0.0"
PORT = int(os.getenv("SSH_HONEYPOT_PORT", os.getenv("COWRIE_SSH_PORT", "2222")))

REDIS_URL = os.getenv("REDIS_URL")
EVENT_STREAM_NAME = os.getenv("EVENT_STREAM_NAME", "autohoneyx:events")
HOST_KEY_PATH = os.getenv("SSH_HOST_KEY_PATH", "/app/ssh_host_key")


def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis

        return redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _publish_attack(payload: dict):
    r = _get_redis()
    event = {
        "event_type": "attack",
        "timestamp": datetime.utcnow().isoformat(),
        "payload": payload,
    }

    if r is None:
        print("REDIS_URL not set; attack event:", event)
        return

    try:
        r.xadd(EVENT_STREAM_NAME, {"data": json.dumps(event)}, maxlen=5000, approximate=True)
    except Exception as e:
        print("Failed to publish to Redis:", e)

def _is_blocked(ip: str) -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        return bool(r.sismember(os.getenv("BLOCKLIST_SET_KEY", "autohoneyx:blocklist"), ip))
    except Exception:
        return False


def _load_or_create_host_key() -> paramiko.PKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class HoneySSHServer(paramiko.ServerInterface):
    def __init__(self, client_addr: tuple[str, int]):
        self.client_addr = client_addr
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        if kind in ("session",):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        _publish_attack(
            {
                "honeypot_type": "ssh",
                "source_ip": self.client_addr[0],
                "source_port": self.client_addr[1],
                "username": username,
                "password": password,
                "event": "auth_attempt",
                "severity": "HIGH",
            }
        )
        # Always fail auth to avoid becoming an interactive shell target
        return paramiko.AUTH_FAILED


def _handle_client(client, addr, host_key):
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        transport.add_server_key(host_key)
        server = HoneySSHServer(addr)
        transport.start_server(server=server)

        # Wait briefly for auth attempts then close
        time.sleep(float(os.getenv("SSH_CONNECTION_HOLD_SECONDS", "3")))
    except Exception as e:
        _publish_attack(
            {
                "honeypot_type": "ssh",
                "source_ip": addr[0],
                "source_port": addr[1],
                "event": "connection_error",
                "error": str(e),
                "severity": "LOW",
            }
        )
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def main():
    host_key = _load_or_create_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    print(f"AutoHoneyX SSH honeypot listening on {HOST}:{PORT}")

    while True:
        client, addr = sock.accept()
        if _is_blocked(addr[0]):
            _publish_attack(
                {
                    "honeypot_type": "ssh",
                    "source_ip": addr[0],
                    "source_port": addr[1],
                    "event": "blocked_connection",
                    "severity": "MEDIUM",
                }
            )
            try:
                client.close()
            except Exception:
                pass
            continue
        _publish_attack(
            {
                "honeypot_type": "ssh",
                "source_ip": addr[0],
                "source_port": addr[1],
                "event": "connection",
                "severity": "MEDIUM",
            }
        )
        t = threading.Thread(target=_handle_client, args=(client, addr, host_key), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
