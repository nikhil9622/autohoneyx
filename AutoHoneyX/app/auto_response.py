"""
Auto-response and tamper-evident audit trail.

Implements safe demo-friendly responses:
- Add IP to Redis-backed blocklist (instant enforcement)
- Persist block decisions to DB
- Emit audit events (hash-chained) to DB and event bus
- Optional notifications via integrations (Slack/GitHub issue)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from app.database import get_db_session
from app.event_bus import BusEvent, get_event_bus
from app.integrations import IntegrationManager
from app.models import AuditEvent, BlockedIP

logger = logging.getLogger(__name__)


BLOCKLIST_SET_KEY = os.getenv("BLOCKLIST_SET_KEY", "autohoneyx:blocklist")


def _get_redis():
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return None
    try:
        import redis

        return redis.from_url(redis_url, decode_responses=True)
    except Exception:
        return None


def is_ip_blocked(ip: str) -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        if not r.sismember(BLOCKLIST_SET_KEY, ip):
            return False
        # If the per-IP TTL key is gone, expire membership
        ttl_key = f"{BLOCKLIST_SET_KEY}:ttl:{ip}"
        if not r.exists(ttl_key):
            r.srem(BLOCKLIST_SET_KEY, ip)
            return False
        return True
    except Exception:
        return False


def block_ip(ip: str, *, reason: str, severity: str, ttl_seconds: int) -> bool:
    r = _get_redis()
    ok = True
    if r is not None:
        try:
            r.sadd(BLOCKLIST_SET_KEY, ip)
            # keep a parallel TTL key so blocks can expire without per-member TTL
            r.setex(f"{BLOCKLIST_SET_KEY}:ttl:{ip}", ttl_seconds, "1")
        except Exception as e:
            logger.warning("Failed to update Redis blocklist: %s", e)
            ok = False

    try:
        with get_db_session() as db:
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            rec = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
            if rec:
                rec.reason = reason
                rec.severity = severity
                rec.is_active = True
                rec.expires_at = expires_at
            else:
                db.add(
                    BlockedIP(
                        ip_address=ip,
                        reason=reason,
                        severity=severity,
                        expires_at=expires_at,
                        is_active=True,
                    )
                )
            db.commit()
    except Exception as e:
        logger.warning("Failed to persist BlockedIP to DB: %s", e)
        ok = False

    return ok


def _compute_audit_hash(prev_hash: str, event_type: str, payload: Dict[str, Any], created_at: str) -> str:
    body = json.dumps({"event_type": event_type, "payload": payload, "created_at": created_at}, sort_keys=True, default=str)
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    h.update(body.encode("utf-8"))
    return h.hexdigest()


async def append_audit_event(event_type: str, payload: Dict[str, Any]) -> Optional[str]:
    created_at = datetime.utcnow().isoformat()
    prev_hash = None
    try:
        with get_db_session() as db:
            last = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).first()
            prev_hash = last.event_hash if last else ""
            event_hash = _compute_audit_hash(prev_hash or "", event_type, payload, created_at)
            db.add(
                AuditEvent(
                    event_type=event_type,
                    payload=payload,
                    prev_hash=prev_hash,
                    event_hash=event_hash,
                )
            )
            db.commit()
    except Exception as e:
        logger.warning("Failed to append audit event: %s", e)
        return None

    # also stream to live UI
    try:
        bus = await get_event_bus()
        await bus.publish(BusEvent(event_type="audit", payload={"event_type": event_type, "hash": event_hash, "payload": payload}, timestamp=created_at))
    except Exception:
        pass

    return event_hash


async def evaluate_and_respond(
    *,
    source_ip: str,
    severity: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Main policy: for HIGH/CRITICAL, block the IP for a demo-friendly TTL and notify.
    """
    actions = []
    ttl = int(os.getenv("BLOCKLIST_TTL_SECONDS", "900"))  # 15 minutes

    should_block = severity in ("HIGH", "CRITICAL")
    if should_block and source_ip and source_ip != "unknown":
        ok = block_ip(source_ip, reason=context.get("reason", "AutoHoneyX auto-response"), severity=severity, ttl_seconds=ttl)
        actions.append({"action": "block_ip", "ip": source_ip, "ttl_seconds": ttl, "success": ok})

    # Notify integrations (safe: only if configured)
    try:
        manager = IntegrationManager()
        await manager.notify_incident(
            {
                "id": context.get("attack_id") or context.get("incident_id"),
                "severity": severity,
                "secret_type": context.get("secret_type"),
                "message": context.get("message") or context.get("reason"),
                "file": context.get("file"),
                "line_number": context.get("line_number"),
                "detected_at": context.get("detected_at") or datetime.utcnow().isoformat(),
            }
        )
        actions.append({"action": "notify_integrations", "success": True})
    except Exception as e:
        actions.append({"action": "notify_integrations", "success": False, "error": str(e)})

    audit_hash = await append_audit_event(
        "auto_response",
        {"source_ip": source_ip, "severity": severity, "actions": actions, "context": context},
    )

    # Stream response event
    try:
        bus = await get_event_bus()
        await bus.publish(
            BusEvent(
                event_type="response",
                payload={"source_ip": source_ip, "severity": severity, "actions": actions, "audit_hash": audit_hash},
                timestamp=datetime.utcnow().isoformat(),
            )
        )
    except Exception:
        pass

    return {"actions": actions, "audit_hash": audit_hash}

