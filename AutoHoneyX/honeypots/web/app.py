from flask import Flask, request, jsonify, make_response
import json
import os
from datetime import datetime

app = Flask(__name__)

REDIS_URL = os.getenv("REDIS_URL")
EVENT_STREAM_NAME = os.getenv("EVENT_STREAM_NAME", "autohoneyx:events")


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


def _client_ip():
    # If behind a reverse proxy, X-Forwarded-For will be present; keep first hop
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def _is_blocked(ip: str) -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        return bool(r.sismember(os.getenv("BLOCKLIST_SET_KEY", "autohoneyx:blocklist"), ip))
    except Exception:
        return False


@app.before_request
def _block_enforcement():
    ip = _client_ip()
    if _is_blocked(ip):
        _publish_attack(
            {
                "honeypot_type": "web",
                "source_ip": ip,
                "user_agent": request.headers.get("User-Agent"),
                "event": "blocked_request",
                "method": request.method,
                "path": request.path,
                "severity": "MEDIUM",
            }
        )
        return make_response("Blocked\n", 403)


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/", methods=["GET", "POST"])
def index():
    _publish_attack(
        {
            "honeypot_type": "web",
            "source_ip": _client_ip(),
            "user_agent": request.headers.get("User-Agent"),
            "event": "request",
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", errors="ignore"),
            "severity": "LOW",
        }
    )
    return "AutoHoneyX Web Honeypot\n", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        body = request.form.to_dict() or (request.get_json(silent=True) or {})
        _publish_attack(
            {
                "honeypot_type": "web",
                "source_ip": _client_ip(),
                "user_agent": request.headers.get("User-Agent"),
                "event": "credential_attempt",
                "username": body.get("username") or body.get("email"),
                "password": body.get("password"),
                "method": request.method,
                "path": request.path,
                "severity": "HIGH",
            }
        )
        # Always fail
        return make_response("Invalid credentials\n", 401)

    # Simple fake login page
    return (
        "<html><body><h3>Login</h3>"
        "<form method='post'>"
        "<input name='username' placeholder='username'/>"
        "<input name='password' placeholder='password' type='password'/>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>",
        200,
    )


@app.route("/admin", methods=["GET"])
def admin():
    _publish_attack(
        {
            "honeypot_type": "web",
            "source_ip": _client_ip(),
            "user_agent": request.headers.get("User-Agent"),
            "event": "admin_probe",
            "method": request.method,
            "path": request.path,
            "severity": "MEDIUM",
        }
    )
    return "Admin panel (honeypot)\n", 200


@app.route("/upload", methods=["POST"])
def upload():
    filename = None
    if "file" in request.files:
        f = request.files["file"]
        filename = f.filename
    _publish_attack(
        {
            "honeypot_type": "web",
            "source_ip": _client_ip(),
            "user_agent": request.headers.get("User-Agent"),
            "event": "upload_attempt",
            "filename": filename,
            "content_type": request.content_type,
            "severity": "MEDIUM",
        }
    )
    return jsonify({"status": "ok"})


@app.route("/.env", methods=["GET"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/phpmyadmin", methods=["GET"])
def common_probes():
    _publish_attack(
        {
            "honeypot_type": "web",
            "source_ip": _client_ip(),
            "user_agent": request.headers.get("User-Agent"),
            "event": "probe",
            "method": request.method,
            "path": request.path,
            "severity": "MEDIUM",
        }
    )
    return "Not found\n", 404


if __name__ == "__main__":
    port = int(os.getenv("WEB_PORT", os.getenv("WEB_HONEYPOT_PORT", "8080")))
    app.run(host="0.0.0.0", port=port)
