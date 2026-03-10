"""
Forensic Artifact Collection Engine
Week 7-9 Implementation: System state capture and forensic preservation
Collects processes, file accesses, network connections, and system logs when token is triggered
"""

import os
import sys
import json
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import psutil

try:
    import winreg
except ImportError:
    winreg = None

from app.database import get_db_session
from app.models import ForensicArtifact, AttackLog

logger = logging.getLogger(__name__)

class Platform:
    """Detect runtime platform"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    
    @staticmethod
    def detect() -> str:
        if sys.platform.startswith('win'):
            return Platform.WINDOWS
        elif sys.platform.startswith('linux'):
            return Platform.LINUX
        elif sys.platform.startswith('darwin'):
            return Platform.MACOS
        return "unknown"

class ForensicsCollector:
    """
    Collects forensic artifacts when a honeytoken is triggered.
    Preserves system state for later analysis and compliance.
    """
    
    def __init__(self):
        self.platform = Platform.detect()
        self.hostname = os.getenv('HOSTNAME') or os.getenv('COMPUTERNAME', 'unknown')
    
    def collect_all(self, attack_log: AttackLog) -> List[ForensicArtifact]:
        """Collect all available forensic artifacts"""
        artifacts = []
        
        # Process artifacts
        artifacts.extend(self.collect_processes())
        
        # Network artifacts
        artifacts.extend(self.collect_network_connections())
        
        # System artifacts
        artifacts.extend(self.collect_system_info())
        
        # Log artifacts
        artifacts.extend(self.collect_system_logs())
        
        # Registry (Windows only)
        if self.platform == Platform.WINDOWS:
            artifacts.extend(self.collect_registry())
        
        # Attach to attack log
        for artifact in artifacts:
            artifact.attack_log_id = str(attack_log.id)
            artifact.system_hostname = self.hostname
        
        return artifacts
    
    def collect_processes(self) -> List[ForensicArtifact]:
        """Collect running processes and their details"""
        artifacts = []
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'status']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'create_time', 'status'])
                    
                    # Get open files
                    try:
                        open_files = [str(f) for f in proc.open_files()]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        open_files = []
                    
                    proc_data = {
                        **pinfo,
                        'open_files': open_files,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    processes.append(proc_data)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Create artifact
            artifact = ForensicArtifact(
                artifact_type='process',
                artifact_data={
                    'process_count': len(processes),
                    'processes': processes[:100],  # Limit to top 100
                    'collection_method': 'psutil'
                },
                severity='MEDIUM',
                collected_at=datetime.utcnow()
            )
            artifacts.append(artifact)
            logger.info(f"Collected {len(processes)} processes")
            
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
        
        return artifacts
    
    def collect_network_connections(self) -> List[ForensicArtifact]:
        """Collect network connections"""
        artifacts = []
        
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                conn_data = {
                    'local_addr': conn.laddr[0] if conn.laddr else None,
                    'local_port': conn.laddr[1] if conn.laddr else None,
                    'remote_addr': conn.remote_addr[0] if conn.remote_addr else None,
                    'remote_port': conn.remote_addr[1] if conn.remote_addr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'timestamp': datetime.utcnow().isoformat()
                }
                connections.append(conn_data)
            
            artifact = ForensicArtifact(
                artifact_type='network',
                artifact_data={
                    'connection_count': len(connections),
                    'connections': connections[:50],  # Limit to active connections
                    'collection_method': 'psutil.net_connections'
                },
                severity='HIGH',
                collected_at=datetime.utcnow()
            )
            artifacts.append(artifact)
            logger.info(f"Collected {len(connections)} network connections")
            
        except Exception as e:
            logger.error(f"Error collecting network connections: {e}")
        
        return artifacts
    
    def collect_system_info(self) -> List[ForensicArtifact]:
        """Collect system information"""
        artifacts = []
        
        try:
            system_data = {
                'hostname': self.hostname,
                'platform': sys.platform,
                'python_version': sys.version,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk_usage': {},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Disk usage
            try:
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        system_data['disk_usage'][partition.mountpoint] = {
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percent': usage.percent
                        }
                    except (OSError, PermissionError):
                        pass
            except Exception as e:
                logger.debug(f"Error collecting disk info: {e}")
            
            artifact = ForensicArtifact(
                artifact_type='system',
                artifact_data=system_data,
                severity='LOW',
                collected_at=datetime.utcnow()
            )
            artifacts.append(artifact)
            logger.info("Collected system information")
            
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
        
        return artifacts
    
    def collect_system_logs(self) -> List[ForensicArtifact]:
        """Collect system logs"""
        artifacts = []
        
        try:
            if self.platform == Platform.WINDOWS:
                artifacts.extend(self._collect_windows_logs())
            elif self.platform == Platform.LINUX:
                artifacts.extend(self._collect_linux_logs())
        except Exception as e:
            logger.error(f"Error collecting system logs: {e}")
        
        return artifacts
    
    def _collect_windows_logs(self) -> List[ForensicArtifact]:
        """Collect Windows Event Logs"""
        artifacts = []
        
        try:
            # Use PowerShell to get recent security logs
            ps_cmd = (
                "Get-EventLog -LogName Security -Newest 100 -AsBaseObject | "
                "Select-Object TimeGenerated, EventID, Message, Computer | "
                "ConvertTo-Json"
            )
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                try:
                    logs = json.loads(result.stdout)
                    if not isinstance(logs, list):
                        logs = [logs]
                except json.JSONDecodeError:
                    logs = []
                
                artifact = ForensicArtifact(
                    artifact_type='security_log',
                    artifact_data={
                        'log_type': 'Windows Security',
                        'entry_count': len(logs),
                        'entries': logs[:50],
                        'collection_method': 'Get-EventLog'
                    },
                    severity='HIGH',
                    collected_at=datetime.utcnow()
                )
                artifacts.append(artifact)
                logger.info(f"Collected {len(logs)} Windows security logs")
        
        except Exception as e:
            logger.error(f"Error collecting Windows logs: {e}")
        
        return artifacts
    
    def _collect_linux_logs(self) -> List[ForensicArtifact]:
        """Collect Linux system logs"""
        artifacts = []
        
        try:
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/journal',
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r', errors='ignore') as f:
                            # Get last 100 lines
                            lines = f.readlines()[-100:]
                        
                        artifact = ForensicArtifact(
                            artifact_type='system_log',
                            artifact_data={
                                'log_file': log_file,
                                'line_count': len(lines),
                                'content': ''.join(lines),
                                'collection_method': 'file_read'
                            },
                            severity='MEDIUM',
                            collected_at=datetime.utcnow()
                        )
                        artifacts.append(artifact)
                        
                    except PermissionError:
                        logger.warning(f"Insufficient permissions for {log_file}")
        
        except Exception as e:
            logger.error(f"Error collecting Linux logs: {e}")
        
        return artifacts
    
    def collect_registry(self) -> List[ForensicArtifact]:
        """Collect Windows registry keys (Windows only)"""
        artifacts = []
        
        if not winreg or self.platform != Platform.WINDOWS:
            return artifacts
        
        try:
            keys_to_check = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services'),
                (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            ]
            
            registry_data = []
            
            for hkey, subkey in keys_to_check:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                registry_data.append({
                                    'key': subkey,
                                    'name': name,
                                    'value': str(value)[:200]  # Truncate long values
                                })
                                i += 1
                            except OSError:
                                break
                except Exception as e:
                    logger.debug(f"Error reading registry {subkey}: {e}")
            
            artifact = ForensicArtifact(
                artifact_type='registry',
                artifact_data={
                    'entries': registry_data,
                    'collection_method': 'winreg'
                },
                severity='MEDIUM',
                collected_at=datetime.utcnow()
            )
            artifacts.append(artifact)
            logger.info(f"Collected {len(registry_data)} registry entries")
            
        except Exception as e:
            logger.error(f"Error collecting registry: {e}")
        
        return artifacts
    
    def store_artifacts(self, artifacts: List[ForensicArtifact]) -> bool:
        """Store forensic artifacts in database"""
        session = get_db_session()
        try:
            for artifact in artifacts:
                session.add(artifact)
            session.commit()
            logger.info(f"Stored {len(artifacts)} forensic artifacts")
            return True
        except Exception as e:
            logger.error(f"Error storing artifacts: {e}")
            return False
        finally:
            session.close()


# Global instance
forensics_collector = None

def init_forensics_collector():
    """Initialize the global forensics collector"""
    global forensics_collector
    forensics_collector = ForensicsCollector()
    logger.info("Forensics collector initialized")

def get_forensics_collector() -> ForensicsCollector:
    """Get or initialize the forensics collector"""
    global forensics_collector
    if forensics_collector is None:
        init_forensics_collector()
    return forensics_collector
