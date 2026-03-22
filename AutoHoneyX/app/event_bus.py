"""
Durable event bus for real-time features.

Primary backend: Redis Streams (durable, consumer groups, ack/retry).
Fallback backend: in-process asyncio Queue (dev-only).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


DEFAULT_STREAM = os.getenv("EVENT_STREAM_NAME", "autohoneyx:events")
DEFAULT_GROUP = os.getenv("EVENT_CONSUMER_GROUP", "api")


@dataclass(frozen=True)
class BusEvent:
    event_type: str  # incident | alert | stats | attack | response | audit
    payload: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {"event_type": self.event_type, "payload": self.payload, "timestamp": self.timestamp}


class EventBus:
    def __init__(self, redis_url: Optional[str] = None, stream: str = DEFAULT_STREAM):
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.stream = stream
        self._redis = None
        self._fallback_q: "asyncio.Queue[BusEvent]" = asyncio.Queue()

    async def connect(self) -> None:
        if not self.redis_url:
            logger.warning("REDIS_URL not set; EventBus using in-process fallback queue (not durable).")
            return
        try:
            import redis.asyncio as redis  # type: ignore

            self._redis = redis.from_url(self.redis_url, decode_responses=True)
            await self._redis.ping()
            logger.info("EventBus connected to Redis")
        except Exception as e:
            logger.exception(f"Failed to connect to Redis; using fallback queue. Error: {e}")
            self._redis = None

    async def publish(self, event: BusEvent) -> str:
        if self._redis is None:
            await self._fallback_q.put(event)
            return "fallback"

        data = {"data": json.dumps(event.to_dict(), ensure_ascii=False)}
        # Keep stream from growing unbounded in demos
        maxlen = int(os.getenv("EVENT_STREAM_MAXLEN", "5000"))
        msg_id = await self._redis.xadd(self.stream, data, maxlen=maxlen, approximate=True)
        return str(msg_id)

    async def ensure_group(self, group: str = DEFAULT_GROUP, start_id: str = "$") -> None:
        if self._redis is None:
            return
        try:
            await self._redis.xgroup_create(self.stream, group, id=start_id, mkstream=True)
        except Exception as e:
            # BUSYGROUP is expected if already exists
            if "BUSYGROUP" not in str(e):
                raise

    async def consume(
        self,
        group: str,
        consumer: str,
        *,
        block_ms: int = 2000,
        count: int = 50,
    ) -> AsyncIterator[Tuple[str, BusEvent]]:
        """
        Yield (message_id, BusEvent). Caller should ack when processed.
        """
        if self._redis is None:
            while True:
                event = await self._fallback_q.get()
                yield ("fallback", event)
            # unreachable

        await self.ensure_group(group)

        while True:
            resp = await self._redis.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={self.stream: ">"},
                count=count,
                block=block_ms,
            )

            if not resp:
                continue

            for _stream_name, messages in resp:
                for msg_id, fields in messages:
                    try:
                        raw = fields.get("data", "{}")
                        obj = json.loads(raw)
                        event = BusEvent(
                            event_type=obj.get("event_type", "unknown"),
                            payload=obj.get("payload") or {},
                            timestamp=obj.get("timestamp") or "",
                        )
                        yield (str(msg_id), event)
                    except Exception as e:
                        logger.error(f"Failed to decode event {msg_id}: {e}")
                        # still yield a best-effort unknown event
                        yield (str(msg_id), BusEvent(event_type="unknown", payload={}, timestamp=""))

    async def ack(self, group: str, msg_id: str) -> None:
        if self._redis is None or msg_id == "fallback":
            return
        try:
            await self._redis.xack(self.stream, group, msg_id)
        except Exception as e:
            logger.warning(f"Failed to ack message {msg_id}: {e}")


_global_bus: Optional[EventBus] = None


async def get_event_bus() -> EventBus:
    global _global_bus
    if _global_bus is None:
        _global_bus = EventBus()
        await _global_bus.connect()
    return _global_bus

