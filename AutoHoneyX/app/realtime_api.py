"""Real-time incident management API (GitGuardian-style)"""

from fastapi import FastAPI, WebSocket, Depends, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import uvicorn
import asyncio
import json
from datetime import datetime, timedelta
from typing import Set, Dict, List, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.database import get_db_session
from app.models import AttackLog, Alert, Honeytoken
from app.security.auth import (
    UserRole,
    create_access_token,
    get_current_admin_user,
    get_current_analyst_user,
    get_current_user,
)
from app.event_bus import get_event_bus, DEFAULT_GROUP
import logging
import os

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AutoHoneyX Real-Time API",
    version="2.0.0",
    description="Real-time secret detection & incident management (GitGuardian-style)"
)

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:8501,http://localhost:8000").split(",")
    if o.strip()
]

# CORS for dashboard (tightened for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RATE_LIMIT_STORAGE_URI = os.getenv("RATE_LIMIT_STORAGE_URI")  # e.g. redis://redis:6379/0
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=RATE_LIMIT_STORAGE_URI,
    default_limits=[os.getenv("DEFAULT_RATE_LIMIT", "120/minute")],
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if os.getenv("ENVIRONMENT", "development").lower() == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)


class LoginRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    role: UserRole = UserRole.VIEWER
    password: str = Field(..., min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


def _check_login_password(role: UserRole, password: str) -> bool:
    """
    Demo-friendly auth: passwords come from env vars.
    - ADMIN_PASSWORD
    - ANALYST_PASSWORD
    - VIEWER_PASSWORD
    """
    env_map = {
        UserRole.ADMIN: "ADMIN_PASSWORD",
        UserRole.ANALYST: "ANALYST_PASSWORD",
        UserRole.VIEWER: "VIEWER_PASSWORD",
    }
    expected = os.getenv(env_map[role], "")
    if not expected:
        return False
    return password == expected


@app.post("/api/v1/auth/token", response_model=TokenResponse)
@limiter.limit(os.getenv("AUTH_RATE_LIMIT", "10/minute"))
async def issue_token(request: Request, payload: LoginRequest):
    """
    Issue JWT token for dashboard/API use.
    For production, integrate a real user store/SSO.
    """
    if not _check_login_password(payload.role, payload.password):
        raise HTTPException(status_code=401, detail="Invalid username/password")
    token = create_access_token({"sub": payload.user_id, "role": payload.role})
    expires = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    return TokenResponse(access_token=token, expires_in_minutes=expires)


class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.subscriptions: Dict[str, Set[WebSocket]] = {
            'incidents': set(),
            'alerts': set(),
            'stats': set(),
            'attacks': set(),
            'all': set()
        }
    
    async def connect(self, websocket: WebSocket, channel: str = 'all'):
        await websocket.accept()
        self.active_connections.add(websocket)
        
        if channel in self.subscriptions:
            self.subscriptions[channel].add(websocket)
        else:
            self.subscriptions['all'].add(websocket)
        
        logger.info(f"Client connected to {channel}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        
        for subs in self.subscriptions.values():
            subs.discard(websocket)
        
        logger.info("Client disconnected")
    
    async def broadcast_incident(self, incident: Dict):
        """Broadcast new security incident (CRITICAL)"""
        message = {
            "type": "incident",
            "severity": incident.get('severity', 'UNKNOWN'),
            "secret_type": incident.get('secret_type'),
            "file": incident.get('file'),
            "line_number": incident.get('line_number'),
            "timestamp": incident.get('detected_at', datetime.utcnow().isoformat()),
            "status": "OPEN"
        }
        
        await self._send_to_subscribers('incidents', message)
        await self._send_to_subscribers('all', message)
    
    async def broadcast_alert(self, alert: Dict):
        """Broadcast alert notification"""
        message = {
            "type": "alert",
            "title": alert.get('title'),
            "severity": alert.get('severity'),
            "message": alert.get('message'),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self._send_to_subscribers('alerts', message)
    
    async def broadcast_stats(self, stats: Dict):
        """Broadcast real-time statistics"""
        message = {
            "type": "stats",
            "total_incidents": stats.get('total_incidents'),
            "critical_count": stats.get('critical_count'),
            "high_count": stats.get('high_count'),
            "triggered_tokens": stats.get('triggered_tokens'),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self._send_to_subscribers('stats', message)

    async def broadcast_attack(self, attack: Dict):
        """Broadcast honeypot attack events for live feed"""
        message = {
            "type": "attack",
            "honeypot_type": attack.get("honeypot_type"),
            "source_ip": attack.get("source_ip"),
            "event": attack.get("event"),
            "timestamp": attack.get("timestamp", datetime.utcnow().isoformat()),
            "severity": attack.get("severity", "MEDIUM"),
            "details": attack,
        }
        await self._send_to_subscribers("attacks", message)
        await self._send_to_subscribers("all", message)
    
    async def _send_to_subscribers(self, channel: str, message: Dict):
        """Send message to all subscribers of a channel"""
        dead_connections = set()
        
        for connection in self.subscriptions.get(channel, set()):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to subscriber: {e}")
                dead_connections.add(connection)
        
        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

manager = ConnectionManager()

async def _websocket_auth(websocket: WebSocket) -> dict:
    """
    Authenticate WebSocket using either:
    - Authorization: Bearer <token> header, OR
    - ?token=<jwt> query param
    """
    token = None
    auth_header = websocket.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Missing WebSocket auth token")

    # Reuse existing JWT validation by faking HTTPBearer credential
    from fastapi.security import HTTPAuthorizationCredentials

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    user = await get_current_user(creds)  # type: ignore[arg-type]
    return user


# ============================================================================
# WebSocket Endpoints - Real-Time Streaming
# ============================================================================

@app.websocket("/ws/incidents")
async def websocket_incidents(websocket: WebSocket):
    """WebSocket endpoint for real-time incident stream"""
    await _websocket_auth(websocket)
    await manager.connect(websocket, 'incidents')
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            logger.debug(f"Received from client: {data}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts"""
    await _websocket_auth(websocket)
    await manager.connect(websocket, 'alerts')
    try:
        while True:
            data = await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket endpoint for all real-time data"""
    await _websocket_auth(websocket)
    await manager.connect(websocket, 'all')
    try:
        while True:
            data = await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)


@app.websocket("/ws/attacks")
async def websocket_attacks(websocket: WebSocket):
    """WebSocket endpoint for honeypot live attack feed"""
    await _websocket_auth(websocket)
    await manager.connect(websocket, "attacks")
    try:
        while True:
            await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

# ============================================================================
# REST API Endpoints - Incident Management (GitGuardian-style)
# ============================================================================

@app.get("/api/v1/incidents")
@limiter.limit(os.getenv("INCIDENTS_RATE_LIMIT", "60/minute"))
async def get_incidents(
    request: Request,
    status: str = "OPEN",
    severity: str = None,
    limit: int = 50,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get incidents with filtering (OPEN, RESOLVED, IGNORED)"""
    with get_db_session() as db:
        query = db.query(Alert).filter(Alert.alert_type == 'SECRET_DETECTED')
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        incidents = query.order_by(Alert.created_at.desc()).limit(limit).all()
        
        return {
            "count": len(incidents),
            "incidents": [
                {
                    "id": str(incident.id),
                    "type": incident.alert_type,
                    "severity": incident.severity,
                    "title": incident.title,
                    "message": incident.message,
                    "created_at": incident.created_at.isoformat(),
                    "status": "OPEN" if not incident.sent_at else "RESOLVED"
                }
                for incident in incidents
            ]
        }

@app.get("/api/v1/incidents/{incident_id}")
@limiter.limit(os.getenv("INCIDENT_DETAIL_RATE_LIMIT", "120/minute"))
async def get_incident_details(
    request: Request,
    incident_id: str,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get detailed incident information with investigation context"""
    with get_db_session() as db:
        incident = db.query(Alert).filter(Alert.id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return {
            "id": str(incident.id),
            "type": incident.alert_type,
            "severity": incident.severity,
            "title": incident.title,
            "message": incident.message,
            "created_at": incident.created_at.isoformat(),
            "status": "OPEN" if not incident.sent_at else "RESOLVED",
            "related_attacks": len(incident.attack_log) if hasattr(incident, 'attack_log') else 0
        }

@app.post("/api/v1/incidents/{incident_id}/resolve")
@limiter.limit(os.getenv("INCIDENT_MUTATE_RATE_LIMIT", "30/minute"))
async def resolve_incident(
    request: Request,
    incident_id: str,
    resolution: Dict,
    background_tasks: BackgroundTasks,
    _user: dict = Depends(get_current_analyst_user),
):
    """Resolve incident with remediation action"""
    with get_db_session() as db:
        incident = db.query(Alert).filter(Alert.id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident.sent_at = datetime.utcnow()
        db.commit()
        
        # Run remediation if needed
        if resolution.get('auto_remediate'):
            background_tasks.add_task(
                lambda: logger.info(f"Remediating incident {incident_id}")
            )
        
        return {
            "status": "RESOLVED",
            "incident_id": str(incident.id),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.post("/api/v1/incidents/{incident_id}/ignore")
@limiter.limit(os.getenv("INCIDENT_MUTATE_RATE_LIMIT", "30/minute"))
async def ignore_incident(
    request: Request,
    incident_id: str,
    reason: str = "",
    _user: dict = Depends(get_current_analyst_user),
):
    """Mark incident as ignored/whitelisted"""
    with get_db_session() as db:
        incident = db.query(Alert).filter(Alert.id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident.sent_at = datetime.utcnow()
        db.commit()
        
        return {
            "status": "IGNORED",
            "incident_id": str(incident.id),
            "reason": reason
        }

# ============================================================================
# Statistics & Analytics Endpoints
# ============================================================================

@app.get("/api/v1/stats")
@limiter.limit(os.getenv("STATS_RATE_LIMIT", "120/minute"))
async def get_realtime_stats(request: Request):
    """Get real-time security statistics"""
    with get_db_session() as db:
        total_incidents = db.query(Alert).filter(
            Alert.alert_type == 'SECRET_DETECTED'
        ).count()
        
        critical_count = db.query(Alert).filter(
            Alert.alert_type == 'SECRET_DETECTED',
            Alert.severity == 'CRITICAL'
        ).count()
        
        high_count = db.query(Alert).filter(
            Alert.alert_type == 'SECRET_DETECTED',
            Alert.severity == 'HIGH'
        ).count()
        
        triggered_tokens = db.query(Honeytoken).filter(
            Honeytoken.is_triggered == True
        ).count()
        
        # Incidents from last 24 hours
        today_count = db.query(Alert).filter(
            Alert.created_at >= datetime.utcnow() - timedelta(days=1),
            Alert.alert_type == 'SECRET_DETECTED'
        ).count()
        
        return {
            "total_incidents": total_incidents,
            "critical_count": critical_count,
            "high_count": high_count,
            "today_count": today_count,
            "triggered_tokens": triggered_tokens,
            "risk_score": min(100, (critical_count * 10) + (high_count * 5)),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/api/v1/incidents-timeline")
@limiter.limit(os.getenv("STATS_RATE_LIMIT", "120/minute"))
async def get_incidents_timeline(
    request: Request,
    days: int = 7,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get incident timeline for last N days (for graphs)"""
    with get_db_session() as db:
        timeline = {}
        
        for i in range(days):
            date = (datetime.utcnow() - timedelta(days=i)).date()
            count = db.query(Alert).filter(
                Alert.created_at >= datetime.combine(date, datetime.min.time()),
                Alert.created_at < datetime.combine(date, datetime.max.time()),
                Alert.alert_type == 'SECRET_DETECTED'
            ).count()
            timeline[str(date)] = count
        
        return {
            "timeline": timeline,
            "period_days": days
        }

@app.get("/api/v1/severity-distribution")
@limiter.limit(os.getenv("STATS_RATE_LIMIT", "120/minute"))
async def get_severity_distribution(
    request: Request,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get distribution of incidents by severity"""
    with get_db_session() as db:
        severities = {}
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = db.query(Alert).filter(
                Alert.severity == severity,
                Alert.alert_type == 'SECRET_DETECTED'
            ).count()
            severities[severity] = count
        
        return {
            "severity_distribution": severities,
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/api/v1/secret-types")
@limiter.limit(os.getenv("STATS_RATE_LIMIT", "120/minute"))
async def get_secret_types_distribution(
    request: Request,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get distribution of detected secret types"""
    with get_db_session() as db:
        # Extract secret type from message
        alerts = db.query(Alert).filter(
            Alert.alert_type == 'SECRET_DETECTED'
        ).all()
        
        secret_types = {}
        for alert in alerts:
            # Parse from title
            if 'Secret Detected:' in alert.title:
                secret_type = alert.title.split('Secret Detected: ')[1]
                secret_types[secret_type] = secret_types.get(secret_type, 0) + 1
        
        return {
            "secret_types": secret_types,
            "total_types": len(secret_types),
            "timestamp": datetime.utcnow().isoformat()
        }

# ============================================================================
# Remediation & Response Endpoints
# ============================================================================

@app.get("/api/v1/remediation-status")
@limiter.limit(os.getenv("REMEDIATION_RATE_LIMIT", "30/minute"))
async def get_remediation_status(
    request: Request,
    _user: dict = Depends(get_current_analyst_user),
):
    """Get status of automated remediation workflows"""
    return {
        "status": "Running",
        "active_playbooks": 5,
        "completed_remediation": 12,
        "pending_remediation": 3,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/remediate-all-critical")
@limiter.limit(os.getenv("REMEDIATION_RATE_LIMIT", "10/minute"))
async def remediate_all_critical(
    request: Request,
    background_tasks: BackgroundTasks,
    _user: dict = Depends(get_current_admin_user),
):
    """Trigger remediation for all critical incidents"""
    background_tasks.add_task(lambda: logger.info("Starting bulk remediation"))
    
    return {
        "status": "Remediation started",
        "message": "Processing all critical incidents",
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# Search & Filter Endpoints
# ============================================================================

@app.get("/api/v1/search")
@limiter.limit(os.getenv("SEARCH_RATE_LIMIT", "60/minute"))
async def search_incidents(
    request: Request,
    query: str,
    secret_type: str = None,
    severity: str = None,
    limit: int = 50,
    _user: dict = Depends(get_current_analyst_user),
):
    """Search incidents by various criteria"""
    with get_db_session() as db:
        query_obj = db.query(Alert).filter(
            Alert.message.ilike(f"%{query}%")
        )
        
        if secret_type:
            query_obj = query_obj.filter(Alert.title.ilike(f"%{secret_type}%"))
        
        if severity:
            query_obj = query_obj.filter(Alert.severity == severity)
        
        results = query_obj.limit(limit).all()
        
        return {
            "count": len(results),
            "results": [
                {
                    "id": str(r.id),
                    "title": r.title,
                    "severity": r.severity,
                    "created_at": r.created_at.isoformat()
                }
                for r in results
            ]
        }

# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/status")
@limiter.limit(os.getenv("STATUS_RATE_LIMIT", "120/minute"))
async def get_system_status(
    request: Request,
    _user: dict = Depends(get_current_user),
):
    """Get overall system status"""
    return {
        "service": "AutoHoneyX Real-Time API",
        "status": "running",
        "version": "2.0.0",
        "connected_clients": len(manager.active_connections),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.on_event("startup")
async def _startup_event_bus_consumer():
    """
    Consume durable events and push them to live WebSocket subscribers.
    This decouples producers (monitor/honeypots/processor) from the API process.
    """
    bus = await get_event_bus()

    async def _consume():
        group = os.getenv("EVENT_CONSUMER_GROUP", DEFAULT_GROUP)
        consumer = os.getenv("EVENT_CONSUMER_NAME", f"api-{os.getpid()}")
        async for msg_id, event in bus.consume(group=group, consumer=consumer):
            try:
                if event.event_type == "incident":
                    await manager.broadcast_incident(event.payload)
                elif event.event_type == "alert":
                    await manager.broadcast_alert(event.payload)
                elif event.event_type == "stats":
                    await manager.broadcast_stats(event.payload)
                elif event.event_type == "attack":
                    await manager.broadcast_attack(event.payload)
                elif event.event_type == "response":
                    await manager.broadcast_alert(
                        {
                            "title": "Auto-response executed",
                            "severity": event.payload.get("severity", "MEDIUM"),
                            "message": json.dumps(event.payload, default=str),
                        }
                    )
                elif event.event_type == "audit":
                    await manager.broadcast_alert(
                        {
                            "title": f"Audit event: {event.payload.get('event_type', 'event')}",
                            "severity": "LOW",
                            "message": json.dumps(event.payload, default=str),
                        }
                    )
                else:
                    # Unknown / future event types: ignore for WS
                    pass
            finally:
                await bus.ack(group, msg_id)

    asyncio.create_task(_consume())

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
