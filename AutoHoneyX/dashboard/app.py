"""Main Streamlit Dashboard Application"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sqlalchemy import func, desc, text
import sys
import os
from pathlib import Path
import io
import zipfile
import hashlib
from typing import Optional, Tuple, List

# Add parent directory to path before imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_db, get_db_session, init_db
import logging
from app.models import Honeytoken, AttackLog, Alert, BehaviorAnalysis
from app.honeytoken_generator import HoneytokenGenerator
from app.injection_engine import InjectionEngine


def _safe_extract_zip(zip_bytes: bytes, dest_dir: Path) -> Path:
    """
    Safely extract a zip to dest_dir.
    Prevents ZipSlip by validating member paths.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for member in zf.infolist():
            if member.filename.endswith("/"):
                continue
            target = (dest_dir / member.filename).resolve()
            if not str(target).startswith(str(dest_dir.resolve())):
                raise ValueError(f"Unsafe zip entry path: {member.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, open(target, "wb") as dst:
                dst.write(src.read())
    return dest_dir


def _list_code_files(root: Path) -> List[Path]:
    exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"}
    files: List[Path] = []
    for ext in exts:
        files.extend(root.rglob(f"*{ext}"))
    pruned: List[Path] = []
    for f in files:
        if any(part in {".git", "__pycache__", "node_modules", ".venv", "venv", "env"} for part in f.parts):
            continue
        pruned.append(f)
    return sorted(set(pruned), key=lambda p: str(p).lower())


def _suggest_injection_points(file_path: Path) -> List[Tuple[int, str]]:
    """
    Heuristic suggestions (line_number, rationale).
    Keeps it simple and demo-friendly.
    """
    try:
        text_content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = text_content.splitlines()
    suggestions: List[Tuple[int, str]] = []

    # After imports
    import_like = ("import ", "from ", "require(")
    last_import = None
    for i, ln in enumerate(lines[:80], start=1):
        s = ln.strip()
        if s.startswith(import_like) or (s.startswith("export ") and " from " in s):
            last_import = i
    if last_import:
        suggestions.append((min(last_import + 1, max(1, len(lines))), "After imports (looks natural; often overlooked)."))

    # Near config/constants
    for i, ln in enumerate(lines[:200], start=1):
        s = ln.strip().lower()
        if any(k in s for k in ["config", "settings", "credentials", "token", "secret", "apikey", "baseurl"]):
            suggestions.append((i, "Near configuration/constants (tempting for attackers)."))
            break

    # Near client/connection wiring
    for i, ln in enumerate(lines[:250], start=1):
        s = ln.strip().lower()
        if any(k in s for k in ["client(", "new ", "connect", "connection", "dsn", "database_url", "auth"]):
            suggestions.append((i, "Near connection/auth wiring (looks realistic)."))
            break

    if not suggestions:
        suggestions.append((1, "Top of file (safe fallback)."))

    seen = set()
    out: List[Tuple[int, str]] = []
    for ln, why in suggestions:
        if ln in seen:
            continue
        seen.add(ln)
        out.append((ln, why))
    return out[:5]


def _render_file_verification(root: Path, rel_path: str, line_number: Optional[int] = None) -> None:
    """
    In-dashboard file viewer that works in Docker.
    Includes: snippet, full-file download, and a clear path hint.
    """
    # Normalize incoming paths (DB may store backslashes from Windows tooling)
    rel_path_norm = str(rel_path).replace("\\", "/").lstrip("/")
    try:
        file_path = (root / rel_path_norm).resolve()
    except Exception:
        st.error("Invalid file path.")
        return

    st.markdown(f"**File:** `{file_path}`")
    if not file_path.exists():
        st.error("File not found at this location.")
        return
    if file_path.is_dir():
        st.error("Expected a file but got a directory.")
        return

    try:
        raw = file_path.read_bytes()
        text_content = raw.decode("utf-8", errors="ignore")
        lines = text_content.splitlines()
    except Exception as e:
        st.error(f"Could not read file: {e}")
        return

    st.download_button(
        "⬇️ Download this file",
        data=raw,
        file_name=file_path.name,
        mime="text/plain",
    )

    if line_number and 1 <= int(line_number) <= max(1, len(lines)):
        ln = int(line_number)
        start = max(1, ln - 5)
        end = min(len(lines), ln + 5)
    else:
        start, end = 1, min(len(lines), 60)

    snippet = []
    for i in range(start, end + 1):
        marker = "👉 " if line_number and i == int(line_number) else "   "
        snippet.append(f"{marker}{i:4d}: {lines[i-1]}")
    st.code("\n".join(snippet) if snippet else "(empty)", language="text")

    # "Open locally" helper: Docker cannot launch host apps, so we generate a command.
    st.markdown("#### Open this location in your editor")
    host_root = st.session_state.get("host_project_root") or os.getenv("HOST_PROJECT_ROOT", "")
    if not host_root:
        st.info("Set **HOST_PROJECT_ROOT** in Settings to enable one-click open commands (e.g. `C:\\Users\\bhave\\Downloads\\AutoHoneyX\\AutoHoneyX`).")
        return

    try:
        # If the file lives under the AutoHoneyX container workspace, compute a relative path.
        autohoneyx_root = Path(__file__).parent.parent.resolve()
        rel_from_root = file_path.relative_to(autohoneyx_root)
    except Exception:
        # Fallback: use the path segment as-is
        rel_from_root = Path(rel_path_norm)

    host_path = str(Path(host_root) / rel_from_root).replace("/", "\\")
    ln = int(line_number) if line_number else 1

    st.caption("Copy/paste one of these into PowerShell on your machine:")
    st.code(f'code -g "{host_path}:{ln}"', language="powershell")
    st.code(f'cursor -g "{host_path}:{ln}"', language="powershell")
    st.code(f'explorer.exe /select,"{host_path}"', language="powershell")


def _resolve_project_root_for_token(rel_path: str) -> Path:
    """
    Best-effort resolver for token file locations across:
    - built-in `test-project`
    - workspace root
    - uploaded ZIP extractions under `honeypot_data/uploads`
    """
    autohoneyx_root = Path(__file__).parent.parent
    rel_path_norm = str(rel_path).replace("\\", "/").lstrip("/")

    candidate_roots = [
        autohoneyx_root / "test-project",
        autohoneyx_root,
        autohoneyx_root / "sample-project-basic",
    ]
    for r in candidate_roots:
        if (r / rel_path_norm).exists():
            return r

    uploads_root = autohoneyx_root / "honeypot_data" / "uploads"
    if uploads_root.exists():
        # One or two-level scan: uploads/<zipname_hash>/... (extracted root)
        for d in sorted([p for p in uploads_root.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True):
            if (d / rel_path_norm).exists():
                return d
            # Sometimes zips contain a top-level folder; allow one extra level
            for child in d.iterdir():
                if child.is_dir() and (child / rel_path_norm).exists():
                    return child

    return autohoneyx_root


def _create_zip_project_honeypot(project_root: Path, *, honeypot_type: str, app_name: str = "admin_portal", listen_port: int = 5005) -> Path:
    """
    Create an "intermediate" honeypot inside an extracted ZIP project folder.
    Currently supported types:
    - "admin_portal": realistic decoy admin portal (Flask) with rich logging
    """
    project_root = project_root.resolve()
    if honeypot_type != "admin_portal":
        raise ValueError(f"Unsupported honeypot_type: {honeypot_type}")

    hp_root = (project_root / app_name).resolve()
    (hp_root / "templates").mkdir(parents=True, exist_ok=True)

    app_py = f"""from flask import Flask, request, render_template, redirect, url_for, session
import json
import time
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

# Write logs inside the project so users can demo it easily.
LOG_PATH = Path(__file__).resolve().parent / "honeypot_interactions.log"

FAKE_USERS = {{
    "admin": "Admin@123!",
    "ops": "Winter2025!",
    "auditor": "ReadOnly#1",
}}

def _log(event_type: str, details: dict):
    record = {{
        "ts": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "details": details,
    }}
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\\n")

@app.route("/")
def index():
    _log("visit", {{}})
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ok = FAKE_USERS.get(username) == password
        _log("login_attempt", {{"username": username, "ok": ok}})
        # Allow entry after logging to keep high-interaction feel.
        session["user"] = username or "guest"
        return redirect(url_for("admin"))
    return render_template("login.html")

@app.route("/admin")
def admin():
    user = session.get("user", "guest")
    _log("admin_view", {{"user": user}})
    return render_template("admin.html", user=user)

@app.route("/admin/export", methods=["POST"])
def export():
    user = session.get("user", "guest")
    scope = request.form.get("scope", "last_24h")
    _log("export_attempt", {{"user": user, "scope": scope}})
    time.sleep(0.3)
    return redirect(url_for("admin"))

@app.route("/admin/rotate-keys", methods=["POST"])
def rotate_keys():
    user = session.get("user", "guest")
    _log("rotate_keys_attempt", {{"user": user}})
    time.sleep(0.2)
    return redirect(url_for("admin"))

@app.route("/admin/diagnostics", methods=["POST"])
def diagnostics():
    user = session.get("user", "guest")
    cmd = request.form.get("cmd", "")
    _log("diagnostics_cmd", {{"user": user, "cmd": cmd}})
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port={int(listen_port)}, debug=False)
"""

    login_html = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Admin Portal</title>
    <style>
      body { font-family: system-ui, Arial; background:#0b1220; color:#e6edf3; }
      .card { max-width: 460px; margin: 8vh auto; background:#111a2e; padding: 24px; border-radius: 12px; border: 1px solid #26324d; }
      input { width: 100%; padding: 10px; margin: 8px 0 14px; border-radius: 8px; border: 1px solid #26324d; background:#0b1220; color:#e6edf3; }
      button { width:100%; padding: 10px; border-radius: 8px; border: 0; background:#ff6b00; color:#111; font-weight: 700; cursor: pointer; }
      small { color:#9fb0c1; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Company Admin Portal</h2>
      <small>SSO degraded. Use break-glass access for emergency operations.</small>
      <form method="post">
        <label>Username</label>
        <input name="username" autocomplete="username" placeholder="admin" />
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" placeholder="••••••••" />
        <button type="submit">Sign in</button>
      </form>
    </div>
  </body>
</html>
"""

    admin_html = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Admin Portal</title>
    <style>
      body { font-family: system-ui, Arial; background:#0b1220; color:#e6edf3; }
      .wrap { max-width: 920px; margin: 6vh auto; padding: 0 18px; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
      .card { background:#111a2e; padding: 18px; border-radius: 12px; border: 1px solid #26324d; }
      input, select { width: 100%; padding: 10px; margin-top: 8px; border-radius: 8px; border: 1px solid #26324d; background:#0b1220; color:#e6edf3; }
      button { margin-top: 10px; padding: 10px 12px; border-radius: 8px; border: 0; background:#ff6b00; color:#111; font-weight: 700; cursor: pointer; }
      code { color:#9fb0c1; }
      small { color:#9fb0c1; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <h2>Admin Portal</h2>
      <p>Signed in as <code>{{ user }}</code></p>
      <div class="grid">
        <div class="card">
          <h3>Exports</h3>
          <small>Exports include audit + billing records.</small>
          <form method="post" action="/admin/export">
            <label>Scope</label>
            <select name="scope">
              <option value="last_24h">Last 24h</option>
              <option value="last_7d">Last 7 days</option>
              <option value="all">All records</option>
            </select>
            <button type="submit">Export CSV</button>
          </form>
        </div>
        <div class="card">
          <h3>Key Management</h3>
          <small>Rotate service keys (requires break-glass approval).</small>
          <form method="post" action="/admin/rotate-keys">
            <button type="submit">Rotate Keys</button>
          </form>
        </div>
        <div class="card">
          <h3>Diagnostics</h3>
          <small>Run diagnostic commands on the edge pool.</small>
          <form method="post" action="/admin/diagnostics">
            <label>Command</label>
            <input name="cmd" placeholder="e.g. whoami; uname -a; cat /etc/passwd" />
            <button type="submit">Run</button>
          </form>
        </div>
        <div class="card">
          <h3>Status</h3>
          <p>Region: <code>us-east-1</code></p>
          <p>Mode: <code>degraded</code></p>
          <p>Last sync: <code>~2m</code></p>
        </div>
      </div>
    </div>
  </body>
</html>
"""

    readme = f"""# Project Honeypot — Admin Portal (Intermediate)

Run:

```bash
python app.py
```

Open:
- http://localhost:{int(listen_port)}

Logs:
- `{app_name}/honeypot_interactions.log`
"""

    (hp_root / "app.py").write_text(app_py, encoding="utf-8")
    (hp_root / "templates" / "login.html").write_text(login_html, encoding="utf-8")
    (hp_root / "templates" / "admin.html").write_text(admin_html, encoding="utf-8")
    (hp_root / "README.md").write_text(readme, encoding="utf-8")
    return hp_root

# Page configuration
st.set_page_config(
    page_title="AutoHoneyX Dashboard",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database (gracefully handle DB failures so Streamlit still starts)
logger = logging.getLogger(__name__)
try:
    init_db()
except Exception as _err:
    # Log exception server-side and show a non-blocking warning in the UI
    logger.exception("Database initialization failed during dashboard startup")
    try:
        st.warning("Database unavailable: running dashboard with limited functionality.")
    except Exception:
        # If Streamlit isn't ready to display warnings yet, ignore
        pass

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #FF6B00;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #FF6B00;
    }
    .alert-critical { background-color: #ff4444; color: white; padding: 1rem; border-radius: 0.5rem; }
    .alert-high { background-color: #ff8800; color: white; padding: 1rem; border-radius: 0.5rem; }
    .alert-medium { background-color: #ffaa00; color: white; padding: 1rem; border-radius: 0.5rem; }
    </style>
""", unsafe_allow_html=True)

def get_stats():
    """Get dashboard statistics"""
    with get_db_session() as db:
        total_tokens = db.query(Honeytoken).count()
        triggered_tokens = db.query(Honeytoken).filter(Honeytoken.is_triggered == True).count()

        total_attacks = db.query(AttackLog).count()
        attacks_24h = db.query(AttackLog).filter(
            AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()

        total_alerts = db.query(Alert).count()
        unread_alerts = db.query(Alert).filter(Alert.is_sent == False).count()

        unique_ips = db.query(func.count(func.distinct(AttackLog.source_ip))).scalar()

    return {
        'total_tokens': total_tokens,
        'triggered_tokens': triggered_tokens,
        'total_attacks': total_attacks,
        'attacks_24h': attacks_24h,
        'total_alerts': total_alerts,
        'unread_alerts': unread_alerts,
        'unique_ips': unique_ips
    }

def main():
    """Main dashboard page"""
    st.markdown('<h1 class="main-header">🍯 AutoHoneyX Security Dashboard</h1>', unsafe_allow_html=True)

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Dashboard", "Honeytokens", "Attack Logs", "Alerts", "Behavior Analysis", "Settings"]
    )

    if page == "Dashboard":
        show_dashboard()
    elif page == "Honeytokens":
        show_honeytokens()
    elif page == "Attack Logs":
        show_attack_logs()
    elif page == "Alerts":
        show_alerts()
    elif page == "Behavior Analysis":
        show_behavior_analysis()
    elif page == "Settings":
        show_settings()

def show_dashboard():
    """Show main dashboard"""
    stats = get_stats()

    # Key metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Honeytokens", stats['total_tokens'])
        st.metric("Triggered", stats['triggered_tokens'],
                 delta=f"{stats['triggered_tokens']/max(stats['total_tokens'],1)*100:.1f}%")

    with col2:
        st.metric("Total Attacks", stats['total_attacks'])
        st.metric("Last 24h", stats['attacks_24h'])

    with col3:
        st.metric("Alerts", stats['total_alerts'])
        st.metric("Unread", stats['unread_alerts'])

    with col4:
        st.metric("Unique IPs", stats['unique_ips'])

    st.divider()

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Attacks Over Time")
        with get_db_session() as db:
            attacks_by_day = db.query(
                func.date(AttackLog.timestamp).label('date'),
                func.count(AttackLog.id).label('count')
            ).filter(
                AttackLog.timestamp >= datetime.utcnow() - timedelta(days=30)
            ).group_by('date').order_by('date').all()

        if attacks_by_day:
            df = pd.DataFrame([(str(d), c) for d, c in attacks_by_day],
                            columns=['Date', 'Count'])
            fig = px.line(df, x='Date', y='Count', title="Attacks by Day")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Attacks by Honeypot Type")
        with get_db_session() as db:
            attacks_by_type = db.query(
                AttackLog.honeypot_type,
                func.count(AttackLog.id).label('count')
            ).group_by(AttackLog.honeypot_type).all()

        if attacks_by_type:
            df = pd.DataFrame(attacks_by_type, columns=['Type', 'Count'])
            fig = px.pie(df, values='Count', names='Type', title="Attack Distribution")
            st.plotly_chart(fig, use_container_width=True)

    # Recent alerts
    st.subheader("Recent Alerts")
    with get_db_session() as db:
        recent_alerts = db.query(Alert).order_by(desc(Alert.created_at)).limit(10).all()

    if recent_alerts:
        alert_data = []
        for alert in recent_alerts:
            alert_data.append({
                'Time': alert.created_at,
                'Severity': alert.severity,
                'Type': alert.alert_type,
                'Title': alert.title,
                'Source IP': str(alert.source_ip) if alert.source_ip else 'N/A'
            })
        df = pd.DataFrame(alert_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet")

def show_honeytokens():
    """Show honeytokens page"""
    st.header("Honeytoken Management")

    # Quick stats at the top
    with get_db_session() as db:
        total_tokens = db.query(Honeytoken).count()
        injected_tokens = db.query(Honeytoken).filter(Honeytoken.location_file.isnot(None)).count()
        active_tokens = db.query(Honeytoken).filter(Honeytoken.is_triggered == False).count()
        triggered_tokens = db.query(Honeytoken).filter(Honeytoken.is_triggered == True).count()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Tokens", total_tokens)
    with col2:
        st.metric("Injected", injected_tokens)
    with col3:
        st.metric("Active", active_tokens)
    with col4:
        st.metric("Triggered", triggered_tokens, delta=f"{triggered_tokens} alerts" if triggered_tokens > 0 else "No alerts")

    if injected_tokens > 0:
        st.info("💡 **Tip:** Click any file location below, then expand the verification section to see the actual token in source code!")
    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["View Tokens", "Generate New", "Injection"])

    with tab1:
        with get_db_session() as db:
            tokens = db.query(Honeytoken).order_by(desc(Honeytoken.created_at)).all()

            # Extract all attributes while session is still open
            token_data = []
            if tokens:
                for token in tokens:
                    # Access all attributes while in session
                    token_id = token.token_id or ''
                    token_type = token.token_type or 'N/A'
                    is_triggered = token.is_triggered or False
                    location_file = token.location_file
                    location_line = token.location_line
                    created = token.created_at
                    triggered = token.triggered_at if is_triggered else None

                    token_data.append({
                        'Token ID': token_id[:12] + '...' if len(token_id) > 12 else token_id,
                        'Type': token_type,
                        'Status': '🔴 Triggered' if is_triggered else '🟢 Active',
                        'Location': f"📁 {location_file}:{location_line}" if location_file else 'N/A',
                        'Created': created,
                        'Triggered': triggered if triggered else 'N/A',
                        'Verify': '🔍 Click to verify' if location_file else 'N/A'
                    })
                active_count = len([t for t in tokens if not (t.is_triggered or False)])
                triggered_count = len([t for t in tokens if t.is_triggered or False])
            else:
                active_count = 0
                triggered_count = 0

        if token_data:
            # Display dataframe with clickable locations
            df = pd.DataFrame(token_data)
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Single, stable verification panel (avoids UI bubbling/jitter)
            st.markdown("### 🔍 Verify a token in its file")
            verifiable = [t for t in tokens if t.location_file]
            if not verifiable:
                st.info("No injected tokens with file locations yet.")
            else:
                options = []
                for t in verifiable:
                    loc = f"{t.location_file}:{t.location_line}" if t.location_line else t.location_file
                    options.append((t.id, f"{(t.token_type or 'N/A').upper()} • {t.token_id[:10]}… • {loc}"))

                selected = st.selectbox(
                    "Select an injected token",
                    options=options,
                    format_func=lambda x: x[1],
                )
                selected_token = next((t for t in verifiable if t.id == selected[0]), None)
                if selected_token:
                    with st.expander("Verification", expanded=True):
                        root = _resolve_project_root_for_token(str(selected_token.location_file))
                        _render_file_verification(
                            root=root,
                            rel_path=str(selected_token.location_file),
                            line_number=int(selected_token.location_line) if selected_token.location_line else None,
                        )

    with tab2:
        st.subheader("Generate New Honeytoken")
        token_type = st.selectbox("Token Type", ['aws', 'db_postgresql', 'db_mysql', 'api', 'ssh'])

        col1, col2 = st.columns(2)
        with col1:
            location_file = st.text_input("File Location (optional)")
        with col2:
            location_line = st.number_input("Line Number (optional)", min_value=1, value=1)

        if st.button("Generate Token"):
            try:
                token_data = None
                if token_type == 'aws':
                    token_data = HoneytokenGenerator.generate_aws_key()
                elif token_type.startswith('db_'):
                    db_type = token_type.replace('db_', '')
                    token_data = HoneytokenGenerator.generate_database_credentials(db_type)
                elif token_type == 'api':
                    token_data = HoneytokenGenerator.generate_api_key()
                elif token_type == 'ssh':
                    token_data = HoneytokenGenerator.generate_ssh_key()

                if token_data:
                    honeytoken = HoneytokenGenerator.save_honeytoken(
                        token_data,
                        location_file=location_file if location_file else None,
                        location_line=location_line if location_line else None
                    )
                    st.success(f"Honeytoken generated: {honeytoken.token_id}")
                    st.code(token_data['token_value'])
                    st.info("Refresh the 'View Tokens' tab to see the new token!")
            except Exception as e:
                st.error(f"Error generating token: {e}")

    with tab3:
        st.subheader("Inject Honeytokens into Repository")
        st.markdown("Upload a ZIP (recommended for demos) or point to a folder under the AutoHoneyX workspace.")

        autohoneyx_root = Path(__file__).parent.parent
        uploads_root = autohoneyx_root / "honeypot_data" / "uploads"
        uploads_root.mkdir(parents=True, exist_ok=True)

        mode = st.radio("Input mode", ["Folder path", "Upload ZIP"], horizontal=True)
        resolved_path: Optional[Path] = None

        if mode == "Folder path":
            repo_path = st.text_input("Project folder (relative to AutoHoneyX)", "sample-project-basic")
            resolved_path = (autohoneyx_root / repo_path).resolve()
            st.caption(f"Resolved: `{resolved_path}`")
        else:
            z = st.file_uploader("Project ZIP", type=["zip"])
            if z is not None:
                data = z.getvalue()
                h = hashlib.sha256(data).hexdigest()[:12]
                dest = uploads_root / f"{Path(z.name).stem}_{h}"
                try:
                    resolved_path = _safe_extract_zip(data, dest)
                    st.success(f"Extracted to `{resolved_path}`")
                except Exception as e:
                    st.error(f"ZIP extract failed: {e}")
                    resolved_path = None

        # Optional features (ZIP-only)
        optional_honeypot_enabled = False
        optional_honeypot_type = "admin_portal"
        optional_honeypot_name = "admin_portal"
        optional_honeypot_port = 5005
        if mode == "Upload ZIP" and resolved_path and resolved_path.exists():
            with st.expander("Optional Features (ZIP projects)", expanded=False):
                st.markdown("#### Add a realistic project honeypot (optional)")
                optional_honeypot_enabled = st.checkbox("Generate a project honeypot inside this ZIP", value=False)
                if optional_honeypot_enabled:
                    st.write("Choose honeypot type to add:")
                    optional_honeypot_type = st.selectbox(
                        "Honeypot type",
                        options=["admin_portal"],
                        format_func=lambda x: "Admin Portal (intermediate, high-interaction style)" if x == "admin_portal" else x,
                    )
                    optional_honeypot_name = st.text_input("Honeypot folder name", value="admin_portal")
                    optional_honeypot_port = st.number_input("Honeypot port (when you run it)", min_value=1024, max_value=65535, value=5005)

        token_types = st.multiselect("Token Types", ['aws', 'db_postgresql', 'api', 'ssh'], default=['aws'])
        files_per_type = st.number_input("Files per Type", min_value=1, max_value=20, value=5)
        tokens_per_file = st.number_input("Tokens per File", min_value=1, max_value=5, value=1)

        target = st.radio("Target", ["Whole folder", "Pick a single file"], horizontal=True)
        selected_file: Optional[Path] = None

        if resolved_path and resolved_path.exists() and target == "Pick a single file":
            code_files = _list_code_files(resolved_path)
            if code_files:
                rels = [str(p.relative_to(resolved_path)).replace("\\", "/") for p in code_files]
                chosen = st.selectbox("Choose a file", options=rels)
                selected_file = (resolved_path / chosen).resolve()

                st.markdown("#### Suggested injection spots (safe + tempting)")
                for ln, why in _suggest_injection_points(selected_file):
                    st.write(f"- **Line {ln}**: {why}")
            else:
                st.warning("No supported code files found in this folder.")

        if st.button("Inject Tokens"):
            try:
                if not resolved_path or not resolved_path.exists():
                    st.error("Path does not exist or ZIP not extracted.")
                    return

                # Apply optional features first (ZIP-only)
                if mode == "Upload ZIP" and optional_honeypot_enabled:
                    hp_root = _create_zip_project_honeypot(
                        resolved_path,
                        honeypot_type=optional_honeypot_type,
                        app_name=optional_honeypot_name.strip() or "admin_portal",
                        listen_port=int(optional_honeypot_port),
                    )
                    st.success(f"Added project honeypot: `{hp_root}`")
                    st.info(f"To run it: `python {hp_root / 'app.py'}` then open `http://localhost:{int(optional_honeypot_port)}`")

                if target == "Pick a single file" and selected_file:
                    engine = InjectionEngine(resolved_path)
                    injections = []
                    for ttype in token_types:
                        injections.extend(
                            engine.inject_into_file(selected_file, ttype, num_injections=int(tokens_per_file))
                        )
                    results = {
                        "total_files_scanned": 1,
                        "files_injected": 1 if injections else 0,
                        "tokens_injected": len(injections),
                        "injections": injections,
                    }
                else:
                    engine = InjectionEngine(resolved_path)
                    results = engine.inject_into_repository(token_types, int(files_per_type), int(tokens_per_file))

                st.success(f"Injected {results['tokens_injected']} tokens into {results['files_injected']} files")
                with st.expander("📊 Injection Details", expanded=True):
                    st.json(results)
                    if results.get("injections"):
                        st.markdown("### 🎯 Recently injected:")
                        for inj in results["injections"][:10]:
                            st.write(f"- `{inj['file']}` — line {inj['line']} — {inj['token_type'].upper()}")
                        st.info("Go to **View Tokens → Verify a token** to see and download the modified file.")
            except Exception as e:
                st.error(f"Error injecting tokens: {e}")
                import traceback
                st.code(traceback.format_exc())

def show_attack_logs():
    """Show attack logs page"""
    st.header("Attack Logs")

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        honeypot_type = st.selectbox("Honeypot Type", ['All', 'ssh', 'web', 'database'])
    with col2:
        time_range = st.selectbox("Time Range", ['Last 24h', 'Last 7 days', 'Last 30 days', 'All'])
    with col3:
        severity_filter = st.selectbox("Severity", ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

    # Query
    with get_db_session() as db:
        query = db.query(AttackLog)

        if honeypot_type != 'All':
            query = query.filter(AttackLog.honeypot_type == honeypot_type)

        if time_range == 'Last 24h':
            query = query.filter(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24))
        elif time_range == 'Last 7 days':
            query = query.filter(AttackLog.timestamp >= datetime.utcnow() - timedelta(days=7))
        elif time_range == 'Last 30 days':
            query = query.filter(AttackLog.timestamp >= datetime.utcnow() - timedelta(days=30))

        if severity_filter != 'All':
            query = query.filter(AttackLog.severity == severity_filter)

        attacks = query.order_by(desc(AttackLog.timestamp)).limit(1000).all()

        # Extract all attributes while session is still open
        attack_data = []
        if attacks:
            for attack in attacks:
                attack_data.append({
                    'Time': attack.timestamp,
                    'Type': attack.honeypot_type or 'N/A',
                    'Source IP': str(attack.source_ip) if attack.source_ip else 'N/A',
                    'Path': attack.request_path[:50] + '...' if attack.request_path and len(attack.request_path) > 50 else (attack.request_path or 'N/A'),
                    'Method': attack.request_method or 'N/A',
                    'Severity': attack.severity or 'N/A',
                    'Classification': attack.classification or 'N/A'
                })

    if attack_data:
        df = pd.DataFrame(attack_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No attacks found matching criteria")

def show_alerts():
    """Show alerts page"""
    st.header("Security Alerts")

    # Filter
    severity = st.selectbox("Filter by Severity", ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

    with get_db_session() as db:
        query = db.query(Alert)
        if severity != 'All':
            query = query.filter(Alert.severity == severity)
        alerts = query.order_by(desc(Alert.created_at)).limit(100).all()

    if alerts:
        for alert in alerts:
            severity_class = f"alert-{alert.severity.lower()}"
            st.markdown(f'<div class="{severity_class}"><h3>{alert.title}</h3><p>{alert.message}</p><small>Time: {alert.created_at} | Type: {alert.alert_type}</small></div>',
                       unsafe_allow_html=True)
            st.markdown("---")
    else:
        st.info("No alerts found")

def show_behavior_analysis():
    """Show behavior analysis page"""
    st.header("Behavioral Analysis")

    with get_db_session() as db:
        analyses = db.query(BehaviorAnalysis).order_by(desc(BehaviorAnalysis.analyzed_at)).limit(100).all()

        # Extract all attributes while session is still open
        if analyses:
            category_counts = {}
            confidence_data = []
            analysis_data = []

            for analysis in analyses:
                category_counts[analysis.category] = category_counts.get(analysis.category, 0) + 1
                if analysis.confidence:
                    confidence_data.append(float(analysis.confidence))
                analysis_data.append({
                    'Time': analysis.analyzed_at,
                    'Category': analysis.category or 'N/A',
                    'Confidence': f"{float(analysis.confidence):.2%}" if analysis.confidence else 'N/A',
                    'Attack Log ID': str(analysis.attack_log_id)[:8] + '...' if analysis.attack_log_id else 'N/A'
                })
        else:
            category_counts = {}
            confidence_data = []
            analysis_data = []

    if analysis_data:
        col1, col2 = st.columns(2)

        with col1:
            if category_counts:
                df = pd.DataFrame(list(category_counts.items()), columns=['Category', 'Count'])
                fig = px.bar(df, x='Category', y='Count', title="Attack Categories")
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            if confidence_data:
                fig = px.histogram(x=confidence_data, nbins=20, title="Confidence Distribution")
                st.plotly_chart(fig, use_container_width=True)

        # Analysis table
        df = pd.DataFrame(analysis_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No behavioral analysis data available yet")


def show_project_honeypot():
    """
    Create a realistic "intermediate" project honeypot inside a selected project folder.
    This is a decoy admin portal with login + admin actions + rich logging.
    """
    st.header("Project Honeypot (Intermediate)")
    st.markdown(
        "Adds a **realistic decoy admin portal** into a target project folder. "
        "It is meant for demos: it looks legitimate and logs attacker interaction."
    )

    autohoneyx_root = Path(__file__).parent.parent
    target_project = st.text_input("Target project folder (relative to AutoHoneyX)", "sample-project-basic")
    project_root = (autohoneyx_root / target_project).resolve()
    st.caption(f"Resolved: `{project_root}`")

    app_name = st.text_input("Honeypot folder name", "admin_portal")
    listen_port = st.number_input("Port to run", min_value=1024, max_value=65535, value=5005)

    st.markdown("#### What will be created")
    st.write(f"- `{app_name}/app.py`")
    st.write(f"- `{app_name}/templates/login.html`")
    st.write(f"- `{app_name}/templates/admin.html`")
    st.write(f"- `{app_name}/README.md`")
    st.write("- Logs to `AutoHoneyX/logs/project_honeypot.log`")

    if st.button("Add Project Honeypot"):
        if not project_root.exists():
            st.error("Target project folder does not exist.")
            return

        hp_root = (project_root / app_name).resolve()
        try:
            (hp_root / "templates").mkdir(parents=True, exist_ok=True)
        except Exception as e:
            st.error(f"Could not create honeypot folder: {e}")
            return

        app_py = f"""from flask import Flask, request, render_template, redirect, url_for, session
import json
import time
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

LOG_PATH = Path(__file__).resolve().parents[2] / "logs" / "project_honeypot.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

FAKE_USERS = {{
    "admin": "Admin@123!",
    "ops": "Winter2025!",
    "auditor": "ReadOnly#1",
}}

def _log(event_type: str, details: dict):
    record = {{
        "ts": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "details": details,
    }}
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\\n")

@app.route("/")
def index():
    _log("visit", {{}})
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ok = FAKE_USERS.get(username) == password
        _log("login_attempt", {{"username": username, "ok": ok}})
        # Always allow entry after logging to keep a high-interaction feel.
        session["user"] = username or "guest"
        return redirect(url_for("admin"))
    return render_template("login.html")

@app.route("/admin")
def admin():
    user = session.get("user", "guest")
    _log("admin_view", {{"user": user}})
    return render_template("admin.html", user=user)

@app.route("/admin/export", methods=["POST"])
def export():
    user = session.get("user", "guest")
    scope = request.form.get("scope", "last_24h")
    _log("export_attempt", {{"user": user, "scope": scope}})
    time.sleep(0.3)
    return redirect(url_for("admin"))

@app.route("/admin/rotate-keys", methods=["POST"])
def rotate_keys():
    user = session.get("user", "guest")
    _log("rotate_keys_attempt", {{"user": user}})
    time.sleep(0.2)
    return redirect(url_for("admin"))

@app.route("/admin/diagnostics", methods=["POST"])
def diagnostics():
    user = session.get("user", "guest")
    cmd = request.form.get("cmd", "")
    _log("diagnostics_cmd", {{"user": user, "cmd": cmd}})
    # Do not execute anything; log only.
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port={int(listen_port)}, debug=False)
"""

        login_html = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Admin Portal</title>
    <style>
      body { font-family: system-ui, Arial; background:#0b1220; color:#e6edf3; }
      .card { max-width: 460px; margin: 8vh auto; background:#111a2e; padding: 24px; border-radius: 12px; border: 1px solid #26324d; }
      input { width: 100%; padding: 10px; margin: 8px 0 14px; border-radius: 8px; border: 1px solid #26324d; background:#0b1220; color:#e6edf3; }
      button { width:100%; padding: 10px; border-radius: 8px; border: 0; background:#ff6b00; color:#111; font-weight: 700; cursor: pointer; }
      small { color:#9fb0c1; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Company Admin Portal</h2>
      <small>SSO degraded. Use break-glass access for emergency operations.</small>
      <form method="post">
        <label>Username</label>
        <input name="username" autocomplete="username" placeholder="admin" />
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" placeholder="••••••••" />
        <button type="submit">Sign in</button>
      </form>
    </div>
  </body>
</html>
"""

        admin_html = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Admin Portal</title>
    <style>
      body { font-family: system-ui, Arial; background:#0b1220; color:#e6edf3; }
      .wrap { max-width: 920px; margin: 6vh auto; padding: 0 18px; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
      .card { background:#111a2e; padding: 18px; border-radius: 12px; border: 1px solid #26324d; }
      input, select { width: 100%; padding: 10px; margin-top: 8px; border-radius: 8px; border: 1px solid #26324d; background:#0b1220; color:#e6edf3; }
      button { margin-top: 10px; padding: 10px 12px; border-radius: 8px; border: 0; background:#ff6b00; color:#111; font-weight: 700; cursor: pointer; }
      code { color:#9fb0c1; }
      small { color:#9fb0c1; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <h2>Admin Portal</h2>
      <p>Signed in as <code>{{ user }}</code></p>
      <div class="grid">
        <div class="card">
          <h3>Exports</h3>
          <small>Exports include audit + billing records.</small>
          <form method="post" action="/admin/export">
            <label>Scope</label>
            <select name="scope">
              <option value="last_24h">Last 24h</option>
              <option value="last_7d">Last 7 days</option>
              <option value="all">All records</option>
            </select>
            <button type="submit">Export CSV</button>
          </form>
        </div>
        <div class="card">
          <h3>Key Management</h3>
          <small>Rotate service keys (requires break-glass approval).</small>
          <form method="post" action="/admin/rotate-keys">
            <button type="submit">Rotate Keys</button>
          </form>
        </div>
        <div class="card">
          <h3>Diagnostics</h3>
          <small>Run diagnostic commands on the edge pool.</small>
          <form method="post" action="/admin/diagnostics">
            <label>Command</label>
            <input name="cmd" placeholder="e.g. whoami; uname -a; cat /etc/passwd" />
            <button type="submit">Run</button>
          </form>
        </div>
        <div class="card">
          <h3>Status</h3>
          <p>Region: <code>us-east-1</code></p>
          <p>Mode: <code>degraded</code></p>
          <p>Last sync: <code>~2m</code></p>
        </div>
      </div>
    </div>
  </body>
</html>
"""

        readme = f"""# Project Honeypot (Intermediate) — Admin Portal

This is a **high-interaction style decoy** admin portal for demos.
It logs all interactions to:

- `AutoHoneyX/logs/project_honeypot.log`

## Run

```bash
python app.py
```

Then open:

- http://localhost:{int(listen_port)}

## Notes
- The portal **does not execute commands**; it only logs attempts.
"""

        try:
            (hp_root / "app.py").write_text(app_py, encoding="utf-8")
            (hp_root / "templates" / "login.html").write_text(login_html, encoding="utf-8")
            (hp_root / "templates" / "admin.html").write_text(admin_html, encoding="utf-8")
            (hp_root / "README.md").write_text(readme, encoding="utf-8")
        except Exception as e:
            st.error(f"Failed writing honeypot files: {e}")
            return

        st.success(f"Added honeypot to `{hp_root}`")
        st.write(f"Run: `python {hp_root / 'app.py'}` → open `http://localhost:{int(listen_port)}`")

def show_settings():
    """Show settings page"""
    st.header("Settings")

    st.subheader("System Configuration")
    st.info("Configuration is managed through environment variables and .env file")

    st.subheader("Editor integration (recommended for demos)")
    default_root = os.getenv("HOST_PROJECT_ROOT", "")
    host_root = st.text_input(
        "HOST_PROJECT_ROOT (Windows path to your AutoHoneyX\\AutoHoneyX folder)",
        value=st.session_state.get("host_project_root", default_root),
        help='Example: C:\\Users\\bhave\\Downloads\\AutoHoneyX\\AutoHoneyX',
    )
    st.session_state["host_project_root"] = host_root.strip()
    st.caption("This is used to generate `code -g` / `cursor -g` commands for opening injected files at the exact line.")

    st.subheader("Database Status")
    try:
        with get_db_session() as db:
            db.execute(text("SELECT 1"))
        st.success("✓ Database connection successful")
    except Exception as e:
        st.error(f"✗ Database connection failed: {e}")

    st.subheader("About")
    st.markdown("""
    **AutoHoneyX v1.0.0**

    Automated Honeypot and Honeytoken Management System

    Features:
    - Honeytoken generation and injection
    - Multiple honeypot types (SSH, Web, Database)
    - Real-time monitoring and alerting
    - Behavioral analysis using ML
    - Comprehensive dashboard
    """)

if __name__ == "__main__":
    main()