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

# Add parent directory to path before imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_db, get_db_session, init_db
import logging
from app.models import Honeytoken, AttackLog, Alert, BehaviorAnalysis
from app.honeytoken_generator import HoneytokenGenerator
from app.injection_engine import InjectionEngine

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
            df = pd.DataFrame([(str(d.date), c) for d, c in attacks_by_day],
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

            # Add verification buttons and expandable sections
            if tokens:
                st.markdown("### 🔍 Verify Tokens in Files")
                st.markdown("**Click the verification buttons below to see the actual token in source code:**")

                # Instead of using st.columns (which requires positive integers),
                # render each verification control in a simple vertical layout.
                for i, token in enumerate(tokens):
                    if token.location_file:
                        verify_key = f"verify_{token.token_id[:8]}_{i}"
                        state_key = f"show_verification_{i}"

                        # Initialize session state if not exists
                        if state_key not in st.session_state:
                            st.session_state[state_key] = False

                        # Button to toggle verification
                        if st.button(f"🔍 Verify {token.location_file}:{token.location_line}", key=verify_key):
                            st.session_state[state_key] = not st.session_state[state_key]

                        # Show current state indicator
                        if st.session_state[state_key]:
                            st.success("✅ Verification Active")
                        else:
                            st.info("Click to verify")

                # Show verification results
                for i, token in enumerate(tokens):
                    if token.location_file and st.session_state.get(f'show_verification_{i}', False):
                        with st.expander(f"📄 {token.location_file}:{token.location_line} - VERIFICATION", expanded=True):
                            # Convert relative path to absolute for display
                            # Token paths are relative to test-project directory
                            autohoneyx_root = Path(__file__).parent.parent
                            test_project_root = autohoneyx_root / "test-project"
                            full_path = (test_project_root / token.location_file).resolve()

                            try:
                                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    lines = f.readlines()

                                if token.location_line and token.location_line <= len(lines):
                                    # Show context around the token line
                                    start_line = max(1, token.location_line - 3)
                                    end_line = min(len(lines), token.location_line + 3)

                                    st.markdown(f"**File:** `{full_path}`")
                                    st.markdown(f"**Token at line {token.location_line}:**")

                                    # Display code with line numbers
                                    code_content = ""
                                    for line_num in range(start_line, end_line + 1):
                                        line_content = lines[line_num - 1].rstrip()
                                        marker = "👉 " if line_num == token.location_line else "   "
                                        code_content += f"{marker}{line_num:3d}: {line_content}\n"

                                    st.code(code_content, language='text')

                                    # Highlight the token line
                                    if token.location_line <= len(lines):
                                        token_line = lines[token.location_line - 1].strip()
                                        if any(keyword in token_line for keyword in ['OLD_AWS_', 'OLD_DB_', 'OLD_API_', 'OLD_SSH_']):
                                            st.success("✅ Token verified at this location!")
                                        else:
                                            st.warning("⚠️ Token pattern not found in expected line")

                                else:
                                    st.error(f"Line {token.location_line} not found in file")

                            except FileNotFoundError:
                                st.error(f"File not found: {full_path}")
                            except Exception as e:
                                st.error(f"Error reading file: {e}")

                            # Add button to open file externally
                            col1, col2 = st.columns(2)
                            with col1:
                                open_key = f"open_{token.token_id[:8]}_{i}"
                                if st.button(f"📂 Open File in Editor", key=open_key):
                                    try:
                                        import os
                                        import subprocess
                                        import platform

                                        file_path = str(full_path)
                                        if platform.system() == "Windows":
                                            os.startfile(file_path)
                                        elif platform.system() == "Darwin":  # macOS
                                            subprocess.run(["open", file_path])
                                        else:  # Linux
                                            subprocess.run(["xdg-open", file_path])

                                        st.success(f"Opening {file_path} in your default editor...")
                                    except Exception as e:
                                        st.error(f"Could not open file: {e}")

                            with col2:
                                refresh_key = f"refresh_{token.token_id[:8]}_{i}"
                                if st.button(f"🔄 Refresh Preview", key=refresh_key):
                                    st.rerun()

                            # Show token details
                            st.markdown("---")
                            st.markdown(f"**Token Details:**")
                            st.write(f"- **ID:** `{token.token_id}`")
                            st.write(f"- **Type:** `{token.token_type}`")
                            st.write(f"- **Created:** `{token.created_at.strftime('%Y-%m-%d %H:%M:%S')}`")
                            st.write(f"- **Status:** `{'TRIGGERED' if token.is_triggered else 'ACTIVE'}`")

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
        repo_path = st.text_input("Repository Path", "../test-project")
        token_types = st.multiselect("Token Types", ['aws', 'db_postgresql', 'api'], default=['aws'])
        files_per_type = st.number_input("Files per Type", min_value=1, max_value=20, value=5)

        if st.button("Inject Tokens"):
            try:
                # Add debugging and better path resolution
                autohoneyx_root = Path(__file__).parent.parent  # Go up from dashboard/ to AutoHoneyX/
                resolved_path = (autohoneyx_root / repo_path).resolve()

                st.info(f"Resolved path: {resolved_path}")
                st.info(f"Path exists: {resolved_path.exists()}")

                if resolved_path.exists():
                    # List files found
                    code_files = []
                    for ext in ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php']:
                        files = list(resolved_path.rglob(f"*{ext}"))
                        if files:
                            code_files.extend(files)
                            st.info(f"Found {len(files)} {ext} files")

                    st.info(f"Total code files found: {len(code_files)}")

                    if code_files:
                        engine = InjectionEngine(resolved_path)
                        results = engine.inject_into_repository(token_types, files_per_type)
                        st.success(f"Injected {results['tokens_injected']} tokens into {results['files_injected']} files")

                        # Show detailed results
                        with st.expander("📊 Injection Details", expanded=True):
                            st.json(results)

                            if results['injections']:
                                st.markdown("### 🎯 Recently Injected Tokens:")
                                for inj in results['injections'][:5]:  # Show first 5
                                    st.write(f"• `{inj['file']}` - Line {inj['line']} - {inj['token_type'].upper()}")

                                st.info("💡 Switch to 'View Tokens' tab above to verify these tokens are in the source code!")

                    else:
                        st.error("No supported code files found in the specified path")
                else:
                    st.error(f"Path does not exist: {resolved_path}")

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

def show_settings():
    """Show settings page"""
    st.header("Settings")

    st.subheader("System Configuration")
    st.info("Configuration is managed through environment variables and .env file")

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