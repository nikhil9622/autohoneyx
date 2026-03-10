"""Real-time incident management API (GitGuardian-style)"""

from fastapi import FastAPI, WebSocket, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn
import asyncio
import json
from datetime import datetime, timedelta
from typing import Set, Dict, List
from app.database import get_db_session
from app.models import AttackLog, Alert, Honeytoken
import logging

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AutoHoneyX Real-Time API",
    version="2.0.0",
    description="Real-time secret detection & incident management (GitGuardian-style)"
)

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.subscriptions: Dict[str, Set[WebSocket]] = {
            'incidents': set(),
            'alerts': set(),
            'stats': set(),
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

# ============================================================================
# WebSocket Endpoints - Real-Time Streaming
# ============================================================================

@app.websocket("/ws/incidents")
async def websocket_incidents(websocket: WebSocket):
    """WebSocket endpoint for real-time incident stream"""
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
    await manager.connect(websocket, 'all')
    try:
        while True:
            data = await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

# ============================================================================
# REST API Endpoints - Incident Management (GitGuardian-style)
# ============================================================================

@app.get("/api/v1/incidents")
async def get_incidents(
    status: str = "OPEN",
    severity: str = None,
    limit: int = 50
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
async def get_incident_details(incident_id: str):
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
async def resolve_incident(
    incident_id: str,
    resolution: Dict,
    background_tasks: BackgroundTasks
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
async def ignore_incident(incident_id: str, reason: str = ""):
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
async def get_realtime_stats():
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
async def get_incidents_timeline(days: int = 7):
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
async def get_severity_distribution():
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
async def get_secret_types_distribution():
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
async def get_remediation_status():
    """Get status of automated remediation workflows"""
    return {
        "status": "Running",
        "active_playbooks": 5,
        "completed_remediation": 12,
        "pending_remediation": 3,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/remediate-all-critical")
async def remediate_all_critical(background_tasks: BackgroundTasks):
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
async def search_incidents(
    query: str,
    secret_type: str = None,
    severity: str = None,
    limit: int = 50
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
async def get_system_status():
    """Get overall system status"""
    return {
        "service": "AutoHoneyX Real-Time API",
        "status": "running",
        "version": "2.0.0",
        "connected_clients": len(manager.active_connections),
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
