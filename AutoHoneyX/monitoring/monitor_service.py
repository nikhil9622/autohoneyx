"""Continuous monitoring service for real-time secret detection"""

import asyncio
import os
import logging
from datetime import datetime, timedelta
from app.realtime_scanner import RealtimeSecretScanner
from app.realtime_api import manager
from app.database import get_db_session
from app.models import Alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MonitoringService:
    """
    Continuous monitoring service that scans for secrets in real-time
    Similar to GitGuardian's background monitoring
    """
    
    def __init__(self):
        self.scanner = RealtimeSecretScanner()
        self.is_running = False
        self.scan_interval = int(os.getenv('SCAN_INTERVAL_SECONDS', 300))  # 5 minutes default
        self.repositories = self._load_monitored_repos()
        self.public_repos = self._load_public_repos()
    
    def _load_monitored_repos(self) -> list:
        """Load list of repositories to monitor"""
        repos = os.getenv('MONITORED_REPOS', '').split(',')
        return [r.strip() for r in repos if r.strip()]
    
    def _load_public_repos(self) -> list:
        """Load list of public repos to monitor (optional)"""
        repos = os.getenv('PUBLIC_REPOS_TO_MONITOR', '').split(',')
        return [r.strip() for r in repos if r.strip()]
    
    async def start(self):
        """Start the monitoring service"""
        logger.info("Starting MonitoringService")
        self.is_running = True
        
        try:
            # Start multiple monitoring tasks
            await asyncio.gather(
                self._monitor_repositories(),
                self._monitor_logs(),
                self._update_statistics(),
                self._check_remediations(),
                return_exceptions=True
            )
        except Exception as e:
            logger.error(f"Error in monitoring service: {e}")
        finally:
            self.is_running = False
    
    async def _monitor_repositories(self):
        """Continuously scan monitored repositories"""
        logger.info("Starting repository monitoring")
        
        while self.is_running:
            try:
                for repo in self.repositories:
                    if not os.path.exists(repo):
                        logger.warning(f"Repository not found: {repo}")
                        continue
                    
                    logger.info(f"Scanning repository: {repo}")
                    
                    # Scan the repository
                    findings = await self.scanner.scan_git_repository(repo)
                    
                    if findings:
                        logger.warning(f"Found {len(findings)} secrets in {repo}")
                        
                        # Process each finding
                        for finding in findings:
                            # Check if already reported
                            if not self._is_duplicate_finding(finding):
                                # Create incident
                                incident_id = await self.scanner.create_incident(finding)
                                
                                # Broadcast to dashboard
                                await manager.broadcast_incident(finding)
                                
                                # Auto-remediate if enabled
                                if os.getenv('AUTO_REMEDIATE', 'false').lower() == 'true':
                                    await self.scanner.automatic_remediation(finding)
                
                # Wait for next scan interval
                await asyncio.sleep(self.scan_interval)
            
            except Exception as e:
                logger.error(f"Error monitoring repositories: {e}")
                await asyncio.sleep(60)  # Retry after 1 minute
    
    async def _monitor_logs(self):
        """Monitor logs for secret patterns"""
        logger.info("Starting log monitoring")
        
        while self.is_running:
            try:
                log_files = self._get_log_files()
                
                for log_file in log_files:
                    try:
                        with open(log_file, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        # Scan log content
                        findings = self.scanner.scan_content(
                            content,
                            {'file': log_file, 'source': 'log_file'}
                        )
                        
                        if findings:
                            for finding in findings:
                                await manager.broadcast_incident(finding)
                    
                    except Exception as e:
                        logger.error(f"Error reading log file {log_file}: {e}")
                
                # Check logs every minute
                await asyncio.sleep(60)
            
            except Exception as e:
                logger.error(f"Error monitoring logs: {e}")
                await asyncio.sleep(60)
    
    async def _update_statistics(self):
        """Update real-time statistics and broadcast"""
        logger.info("Starting statistics update")
        
        while self.is_running:
            try:
                with get_db_session() as db:
                    # Get current stats
                    total_incidents = db.query(Alert).filter(
                        Alert.alert_type == 'SECRET_DETECTED'
                    ).count()
                    
                    critical_count = db.query(Alert).filter(
                        Alert.severity == 'CRITICAL'
                    ).count()
                    
                    high_count = db.query(Alert).filter(
                        Alert.severity == 'HIGH'
                    ).count()
                    
                    stats = {
                        'total_incidents': total_incidents,
                        'critical_count': critical_count,
                        'high_count': high_count,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    # Broadcast stats update
                    await manager.broadcast_stats(stats)
                
                # Update every 30 seconds
                await asyncio.sleep(30)
            
            except Exception as e:
                logger.error(f"Error updating statistics: {e}")
                await asyncio.sleep(30)
    
    async def _check_remediations(self):
        """Check status of automated remediation workflows"""
        logger.info("Starting remediation monitor")
        
        while self.is_running:
            try:
                # Get open incidents
                with get_db_session() as db:
                    open_incidents = db.query(Alert).filter(
                        Alert.alert_type == 'SECRET_DETECTED',
                        Alert.sent_at == None
                    ).all()
                    
                    for incident in open_incidents:
                        # Check if should be auto-remediated
                        if os.getenv('AUTO_REMEDIATE', 'false').lower() == 'true':
                            # Extract secret type from title
                            if 'Secret Detected:' in incident.title:
                                secret_type = incident.title.split('Secret Detected: ')[1]
                                
                                finding = {
                                    'secret_type': secret_type,
                                    'file': incident.message
                                }
                                
                                # Try to remediate
                                success = await self.scanner.automatic_remediation(finding)
                                
                                if success:
                                    incident.sent_at = datetime.utcnow()
                                    db.commit()
                                    logger.info(f"Remediated incident: {incident.id}")
                
                # Check every 5 minutes
                await asyncio.sleep(300)
            
            except Exception as e:
                logger.error(f"Error checking remediations: {e}")
                await asyncio.sleep(300)
    
    def _get_log_files(self) -> list:
        """Get list of log files to monitor"""
        log_dirs = [
            './logs',
            '/var/log/autohoneyx',
            os.path.expanduser('~/.autohoneyx/logs')
        ]
        
        log_files = []
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                for file in os.listdir(log_dir):
                    if file.endswith('.log'):
                        log_files.append(os.path.join(log_dir, file))
        
        return log_files
    
    def _is_duplicate_finding(self, finding: dict) -> bool:
        """Check if this finding was already reported recently"""
        try:
            with get_db_session() as db:
                # Check if same file/line within last hour
                recent = db.query(Alert).filter(
                    Alert.title.ilike(f"%{finding.get('secret_type')}%"),
                    Alert.message.ilike(f"%{finding.get('file')}%"),
                    Alert.created_at >= datetime.utcnow() - timedelta(hours=1)
                ).first()
                
                return recent is not None
        except:
            return False


async def run_monitoring():
    """Run monitoring service"""
    service = MonitoringService()
    await service.start()


if __name__ == "__main__":
    # Run monitoring service
    asyncio.run(run_monitoring())
