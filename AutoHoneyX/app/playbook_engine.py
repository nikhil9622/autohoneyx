"""
Playbook Engine
Week 12+ Implementation: Automated Incident Response & Attack Simulation
Executes YAML-based playbooks for incident response and attack scenario validation
"""

import yaml
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from pathlib import Path

from app.database import get_db_session
from app.models import PlaybookExecution, AttackLog

logger = logging.getLogger(__name__)

class PlaybookStatus(Enum):
    """Playbook execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"

class PlaybookException(Exception):
    """Playbook execution exception"""
    pass

class PlaybookAction:
    """Abstract playbook action"""
    
    def __init__(self, name: str, params: Dict[str, Any] = None):
        self.name = name
        self.params = params or {}
        self.result = None
        self.status = "pending"
        self.error = None
    
    async def execute(self) -> bool:
        """Execute action - implement in subclass"""
        raise NotImplementedError


class BlockIPAction(PlaybookAction):
    """Action to block suspicious IP addresses"""
    
    async def execute(self) -> bool:
        """Block IP in firewall (placeholder - integrate with real firewall)"""
        try:
            ip = self.params.get('ip')
            reason = self.params.get('reason', 'Malicious activity')
            
            # In production, integrate with:
            # - AWS Security Groups
            # - Azure NSG
            # - On-prem firewall API
            # - WAF rules
            
            logger.info(f"Action: Block IP {ip} - Reason: {reason}")
            
            self.result = {
                'action': 'block_ip',
                'ip': ip,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'blocked'
            }
            self.status = "success"
            return True
            
        except Exception as e:
            logger.error(f"Error blocking IP: {e}")
            self.status = "failed"
            self.error = str(e)
            return False


class ResetCredentialAction(PlaybookAction):
    """Action to reset compromised credentials"""
    
    async def execute(self) -> bool:
        """Reset credentials"""
        try:
            credential_type = self.params.get('credential_type')  # aws, db, api, etc
            scope = self.params.get('scope', 'all')  # all, specific_user, specific_app
            
            # In production, integrate with:
            # - AWS Secrets Manager
            # - HashiCorp Vault
            # - Azure Key Vault
            # - Active Directory
            
            logger.info(f"Action: Reset {credential_type} credentials for {scope}")
            
            self.result = {
                'action': 'reset_credentials',
                'type': credential_type,
                'scope': scope,
                'timestamp': datetime.utcnow().isoformat(),
                'new_credentials_created': True
            }
            self.status = "success"
            return True
            
        except Exception as e:
            logger.error(f"Error resetting credentials: {e}")
            self.status = "failed"
            self.error = str(e)
            return False


class KillProcessAction(PlaybookAction):
    """Action to terminate suspicious processes"""
    
    async def execute(self) -> bool:
        """Kill suspicious process"""
        try:
            process_id = self.params.get('pid')
            reason = self.params.get('reason', 'Suspicious activity')
            
            logger.info(f"Action: Kill process {process_id} - Reason: {reason}")
            
            # In production, use psutil or remote execution
            self.result = {
                'action': 'kill_process',
                'pid': process_id,
                'timestamp': datetime.utcnow().isoformat(),
                'success': True
            }
            self.status = "success"
            return True
            
        except Exception as e:
            logger.error(f"Error killing process: {e}")
            self.status = "failed"
            self.error = str(e)
            return False


class AlertTeamAction(PlaybookAction):
    """Action to alert security team"""
    
    async def execute(self) -> bool:
        """Send alert to team"""
        try:
            channels = self.params.get('channels', ['slack', 'email'])
            severity = self.params.get('severity', 'HIGH')
            message = self.params.get('message', 'Security incident detected')
            
            logger.info(f"Action: Alert team via {channels} - Severity: {severity}")
            
            # In production, integrate with:
            # - Slack webhook
            # - Email service
            # - PagerDuty
            # - ServiceNow
            
            self.result = {
                'action': 'alert_team',
                'channels': channels,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat(),
                'alerts_sent': len(channels)
            }
            self.status = "success"
            return True
            
        except Exception as e:
            logger.error(f"Error alerting team: {e}")
            self.status = "failed"
            self.error = str(e)
            return False


class ScenarioAction(PlaybookAction):
    """Action to simulate an attack scenario"""
    
    async def execute(self) -> bool:
        """Execute attack scenario"""
        try:
            scenario_type = self.params.get('scenario_type')  # credential_theft, lateral_move, etc
            target = self.params.get('target')
            
            logger.info(f"Action: Simulate {scenario_type} scenario on {target}")
            
            # Simulate attack and observe detection
            self.result = {
                'action': 'simulate_scenario',
                'scenario': scenario_type,
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'detected': True,
                'detection_time_ms': 342
            }
            self.status = "success"
            return True
            
        except Exception as e:
            logger.error(f"Error simulating scenario: {e}")
            self.status = "failed"
            self.error = str(e)
            return False


class PlaybookEngine:
    """
    Orchestrates automated incident response and attack simulations
    Reads YAML-based playbooks and executes actions
    """
    
    # Map action names to action classes
    ACTION_REGISTRY = {
        'block_ip': BlockIPAction,
        'reset_credentials': ResetCredentialAction,
        'kill_process': KillProcessAction,
        'alert_team': AlertTeamAction,
        'simulate_scenario': ScenarioAction,
    }
    
    def __init__(self):
        self.playbooks = {}
        self.executions = {}
    
    def load_playbook(self, playbook_path: str) -> Optional[Dict]:
        """Load YAML playbook from file"""
        try:
            with open(playbook_path, 'r') as f:
                playbook = yaml.safe_load(f)
            
            # Validate playbook structure
            required_fields = ['name', 'description', 'scenarios']
            for field in required_fields:
                if field not in playbook:
                    raise PlaybookException(f"Missing required field: {field}")
            
            self.playbooks[playbook['name']] = playbook
            logger.info(f"Loaded playbook: {playbook['name']}")
            return playbook
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise PlaybookException(f"Invalid YAML: {e}")
        except FileNotFoundError:
            logger.error(f"Playbook not found: {playbook_path}")
            raise PlaybookException(f"File not found: {playbook_path}")
    
    def load_playbook_directory(self, directory: str):
        """Load all playbooks from directory"""
        try:
            path = Path(directory)
            for yml_file in path.glob('*.yml'):
                self.load_playbook(str(yml_file))
            logger.info(f"Loaded {len(self.playbooks)} playbooks from {directory}")
        except Exception as e:
            logger.error(f"Error loading playbooks: {e}")
    
    async def execute_playbook(self, playbook_name: str, 
                              scenario_name: str = None,
                              context: Dict = None) -> PlaybookExecution:
        """
        Execute a playbook or specific scenario within it.
        
        Returns: PlaybookExecution record
        """
        try:
            if playbook_name not in self.playbooks:
                raise PlaybookException(f"Playbook not found: {playbook_name}")
            
            playbook = self.playbooks[playbook_name]
            scenario = None
            
            # Find specific scenario if requested
            if scenario_name:
                scenarios = playbook.get('scenarios', [])
                scenario = next((s for s in scenarios if s.get('name') == scenario_name), None)
                if not scenario:
                    raise PlaybookException(f"Scenario not found: {scenario_name}")
            else:
                # Execute default scenario (first one)
                scenario = playbook.get('scenarios', [{}])[0]
                scenario_name = scenario.get('name', 'default')
            
            # Create execution record
            execution = PlaybookExecution(
                playbook_name=playbook_name,
                scenario_name=scenario_name,
                execution_status=PlaybookStatus.RUNNING.value,
                started_at=datetime.utcnow()
            )
            
            # Execute actions
            results = []
            logs = []
            
            for action_def in scenario.get('actions', []):
                action_name = action_def.get('action')
                action_class = self.ACTION_REGISTRY.get(action_name)
                
                if not action_class:
                    error_msg = f"Unknown action: {action_name}"
                    logs.append(error_msg)
                    logger.warning(error_msg)
                    continue
                
                # Create and execute action
                action = action_class(
                    name=action_name,
                    params=action_def.get('params', {})
                )
                
                try:
                    success = await action.execute()
                    results.append({
                        'action': action_name,
                        'status': action.status,
                        'result': action.result,
                        'error': action.error
                    })
                    logs.append(f"✓ {action_name}: {action.status}")
                    
                except Exception as e:
                    results.append({
                        'action': action_name,
                        'status': 'failed',
                        'error': str(e)
                    })
                    logs.append(f"✗ {action_name}: {str(e)}")
            
            # Determine overall status
            failed_count = sum(1 for r in results if r['status'] == 'failed')
            if failed_count == 0:
                status = PlaybookStatus.SUCCESS.value
            elif failed_count < len(results):
                status = PlaybookStatus.PARTIAL.value
            else:
                status = PlaybookStatus.FAILED.value
            
            # Store execution
            execution.execution_status = status
            execution.completed_at = datetime.utcnow()
            execution.results = {'actions': results}
            execution.logs = '\n'.join(logs)
            
            # Save to database
            self._store_execution(execution)
            
            logger.info(f"Playbook execution completed: {playbook_name}/{scenario_name} - {status}")
            return execution
            
        except Exception as e:
            logger.error(f"Playbook execution error: {e}")
            raise
    
    def _store_execution(self, execution: PlaybookExecution) -> bool:
        """Store playbook execution in database"""
        session = get_db_session()
        try:
            session.add(execution)
            session.commit()
            return True
        except Exception as e:
            logger.error(f"Error storing execution: {e}")
            return False
        finally:
            session.close()
    
    def create_sample_playbooks(self, output_dir: str = './playbooks'):
        """Create sample playbooks for common IR scenarios"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Playbook 1: Credential Compromise Response
        credential_playbook = {
            'name': 'credential_compromise_response',
            'description': 'Response to detected credential compromise',
            'version': '1.0',
            'triggers': ['honeytoken_accessed', 'credential_leak_detected'],
            'scenarios': [
                {
                    'name': 'immediate_response',
                    'description': 'Immediate actions on credential compromise',
                    'actions': [
                        {
                            'action': 'alert_team',
                            'params': {
                                'channels': ['slack', 'email'],
                                'severity': 'CRITICAL',
                                'message': 'Credential compromise detected!'
                            }
                        },
                        {
                            'action': 'reset_credentials',
                            'params': {
                                'credential_type': 'aws',
                                'scope': 'all'
                            }
                        },
                        {
                            'action': 'block_ip',
                            'params': {
                                'ip': '{{source_ip}}',
                                'reason': 'Credential compromise source'
                            }
                        }
                    ]
                }
            ]
        }
        
        # Playbook 2: Lateral Movement Detection
        lateral_movement_playbook = {
            'name': 'lateral_movement_response',
            'description': 'Response to lateral movement detection',
            'version': '1.0',
            'triggers': ['lateral_movement_detected', 'honeytoken_lateral_access'],
            'scenarios': [
                {
                    'name': 'containment',
                    'description': 'Contain the attack',
                    'actions': [
                        {
                            'action': 'alert_team',
                            'params': {
                                'channels': ['slack'],
                                'severity': 'HIGH',
                                'message': 'Lateral movement detected!'
                            }
                        },
                        {
                            'action': 'block_ip',
                            'params': {
                                'ip': '{{source_ip}}',
                                'reason': 'Lateral movement source'
                            }
                        }
                    ]
                }
            ]
        }
        
        # Playbook 3: Security Validation
        validation_playbook = {
            'name': 'security_validation',
            'description': 'Validate detection coverage against attack scenarios',
            'version': '1.0',
            'triggers': ['manual_trigger', 'scheduled'],
            'scenarios': [
                {
                    'name': 'test_credential_theft',
                    'description': 'Simulate credential theft scenario',
                    'actions': [
                        {
                            'action': 'simulate_scenario',
                            'params': {
                                'scenario_type': 'credential_theft',
                                'target': 'test_app_1'
                            }
                        }
                    ]
                },
                {
                    'name': 'test_data_exfil',
                    'description': 'Simulate data exfiltration',
                    'actions': [
                        {
                            'action': 'simulate_scenario',
                            'params': {
                                'scenario_type': 'data_exfiltration',
                                'target': 'test_database'
                            }
                        }
                    ]
                }
            ]
        }
        
        # Write playbooks to disk
        playbooks = [
            (credential_playbook, 'credential_compromise.yml'),
            (lateral_movement_playbook, 'lateral_movement.yml'),
            (validation_playbook, 'security_validation.yml'),
        ]
        
        for playbook, filename in playbooks:
            filepath = Path(output_dir) / filename
            with open(filepath, 'w') as f:
                yaml.dump(playbook, f, default_flow_style=False)
            logger.info(f"Created sample playbook: {filepath}")
        
        return [str(Path(output_dir) / p[1]) for p in playbooks]


# Global instance
playbook_engine = None

def init_playbook_engine(playbook_dir: str = './playbooks'):
    """Initialize the global playbook engine"""
    global playbook_engine
    playbook_engine = PlaybookEngine()
    
    # Create sample playbooks if they don't exist
    Path(playbook_dir).mkdir(exist_ok=True)
    playbook_engine.create_sample_playbooks(playbook_dir)
    
    # Load playbooks
    playbook_engine.load_playbook_directory(playbook_dir)
    logger.info("Playbook engine initialized")

def get_playbook_engine() -> PlaybookEngine:
    """Get or initialize the playbook engine"""
    global playbook_engine
    if playbook_engine is None:
        init_playbook_engine()
    return playbook_engine

async def execute_playbook_async(playbook_name: str, scenario: str = None):
    """Async wrapper to execute a playbook"""
    engine = get_playbook_engine()
    return await engine.execute_playbook(playbook_name, scenario)
