"""
Consume honeypot attack events from the durable event bus and run analysis.

This is the glue between:
- honeypots emitting `event_type="attack"` events
- the analysis pipeline in `app/realtime_event_processor.py`
"""

import asyncio
import logging
import os

from app.event_bus import DEFAULT_GROUP, get_event_bus
from app.realtime_event_processor import get_event_processor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_attack_consumer():
    bus = await get_event_bus()
    processor = get_event_processor()

    # Start background analysis workers
    worker_count = int(os.getenv("ATTACK_PROCESSOR_WORKERS", "3"))
    asyncio.create_task(processor.start_processing(num_workers=worker_count))

    group = os.getenv("ATTACK_CONSUMER_GROUP", "processor")
    consumer = os.getenv("ATTACK_CONSUMER_NAME", f"processor-{os.getpid()}")

    logger.info("Attack consumer started (group=%s consumer=%s)", group, consumer)

    async for msg_id, event in bus.consume(group=group, consumer=consumer):
        try:
            if event.event_type != "attack":
                continue
            await processor.process_attack_event(event.payload)
        except Exception as e:
            logger.exception("Error processing attack event: %s", e)
        finally:
            await bus.ack(group, msg_id)


if __name__ == "__main__":
    asyncio.run(run_attack_consumer())

