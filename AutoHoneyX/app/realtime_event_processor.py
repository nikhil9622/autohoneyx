"""
Realtime Event Processor
Hooks into honeytoken triggers and runs the full analysis pipeline
Coordinates between honeypot events and analysis engines
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from app.database import get_db_session
from app.models import AttackLog, Alert, Honeytoken
from app.incident_orchestrator import get_orchestrator

logger = logging.getLogger(__name__)

class RealtimeEventProcessor:
    """
    Processes honeytoken trigger events in real-time.
    When a honeytoken is accessed, this processor:
    1. Records the AttackLog event
    2. Runs full incident analysis pipeline
    3. Stores results and creates alerts
    4. Triggers automated responses if needed
    """
    
    def __init__(self):
        self.orchestrator = get_orchestrator()
        self.processing_queue = asyncio.Queue()
        self.processed_count = 0
        self.error_count = 0
    
    async def process_honeytoken_trigger(self, 
                                        honeytoken_id: str,
                                        source_ip: str,
                                        honeypot_type: str,
                                        user_agent: str = None,
                                        request_data: Dict = None) -> Optional[AttackLog]:
        """
        Handle honeytoken trigger event.
        This is the entry point when a honeytoken is accessed.
        
        Args:
            honeytoken_id: ID of triggered honeytoken
            source_ip: Attacking source IP
            honeypot_type: Type of honeypot (ssh, web, db, etc)
            user_agent: HTTP user agent (if applicable)
            request_data: Additional request context
        
        Returns:
            AttackLog instance created, or None on error
        """
        session = get_db_session()
        try:
            # Create attack log record
            attack_log = AttackLog(
                honeypot_type=honeypot_type,
                source_ip=source_ip,
                user_agent=user_agent,
                request_method=request_data.get('method') if request_data else None,
                request_path=request_data.get('path') if request_data else None,
                request_body=request_data.get('body') if request_data else None,
                response_code=200,
                timestamp=datetime.utcnow(),
                severity='MEDIUM',  # Will be updated by orchestrator
                attack_metadata=request_data or {}
            )
            
            # Link to honeytoken if available
            honeytoken = session.query(Honeytoken).filter(
                Honeytoken.id == honeytoken_id
            ).first()
            
            if honeytoken:
                attack_log.honeytoken_id = honeytoken.id
                honeytoken.triggered_at = datetime.utcnow()
                honeytoken.triggered_by_ip = source_ip
                honeytoken.triggered_by_user_agent = user_agent
                honeytoken.is_triggered = True
                session.merge(honeytoken)
            
            session.add(attack_log)
            session.commit()
            
            logger.info(f"Created attack log: {attack_log.id} from {source_ip}")
            
            # Queue for async processing
            await self.processing_queue.put(attack_log)
            
            return attack_log
            
        except Exception as e:
            logger.error(f"Error creating attack log: {e}")
            self.error_count += 1
            return None
        finally:
            session.close()
    
    async def start_processing(self, num_workers: int = 3):
        """
        Start background workers that process events from queue.
        Each worker runs full incident analysis pipeline.
        
        Args:
            num_workers: Number of async workers to spawn
        """
        logger.info(f"Starting {num_workers} event processors...")
        
        workers = [
            asyncio.create_task(self._process_worker(f"worker-{i}"))
            for i in range(num_workers)
        ]
        
        await asyncio.gather(*workers)
    
    async def _process_worker(self, worker_id: str):
        """
        Individual worker that processes events from queue.
        Runs orchestrator pipeline for each event.
        """
        logger.info(f"{worker_id} started")
        
        while True:
            try:
                # Get event from queue (timeout prevents blocking)
                attack_log = await asyncio.wait_for(
                    self.processing_queue.get(),
                    timeout=30
                )
                
                logger.info(f"{worker_id}: Processing attack {attack_log.id}")
                
                try:
                    # Run full analysis pipeline
                    report = await self.orchestrator.process_attack(attack_log)
                    self.processed_count += 1
                    
                    logger.info(f"{worker_id}: Completed analysis for {attack_log.id}")
                    logger.debug(f"Report: {report}")
                    
                except Exception as e:
                    logger.error(f"{worker_id}: Error processing attack: {e}")
                    self.error_count += 1
                
                # Mark task as done
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                # Queue empty, continue checking
                continue
            except Exception as e:
                logger.error(f"{worker_id}: Unexpected error: {e}")
    
    async def process_batch(self, attack_logs: List[AttackLog]) -> List[Dict]:
        """
        Process multiple attack logs in batch.
        Useful for bulk analysis or historical data.
        
        Args:
            attack_logs: List of AttackLog instances to process
        
        Returns:
            List of analysis reports
        """
        logger.info(f"Batch processing {len(attack_logs)} attacks...")
        
        reports = await self.orchestrator.batch_process_attacks(attack_logs)
        self.processed_count += len(attack_logs)
        
        return reports
    
    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics"""
        return {
            'processed': self.processed_count,
            'errors': self.error_count,
            'queue_size': self.processing_queue.qsize()
        }


# Global instance
event_processor = None

def init_event_processor():
    """Initialize the global realtime event processor"""
    global event_processor
    event_processor = RealtimeEventProcessor()
    logger.info("Realtime event processor initialized")

def get_event_processor() -> RealtimeEventProcessor:
    """Get or initialize the event processor"""
    global event_processor
    if event_processor is None:
        init_event_processor()
    return event_processor

async def handle_honeytoken_trigger(honeytoken_id: str,
                                   source_ip: str,
                                   honeypot_type: str,
                                   user_agent: str = None,
                                   request_data: Dict = None) -> Optional[AttackLog]:
    """
    Convenient async function to handle a honeytoken trigger.
    
    Usage from honeypot handlers:
    ```python
    from app.realtime_event_processor import handle_honeytoken_trigger
    
    # When honeytoken is triggered:
    await handle_honeytoken_trigger(
        honeytoken_id=token.id,
        source_ip=request.remote_addr,
        honeypot_type='web',
        user_agent=request.headers.get('User-Agent'),
        request_data={
            'method': request.method,
            'path': request.path,
            'body': request.data
        }
    )
    ```
    """
    processor = get_event_processor()
    return await processor.process_honeytoken_trigger(
        honeytoken_id,
        source_ip,
        honeypot_type,
        user_agent,
        request_data
    )
