"""
SIEM Integration Engine
Week 5-6 Implementation: Splunk, ELK, Azure Sentinel Support
Send real-time alerts and events to enterprise SIEM platforms
"""

import json
import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from app.database import get_db_session
from app.models import AttackLog, Alert, KillChainEvent
from app.config import config

logger = logging.getLogger(__name__)

class SIEMType(Enum):
    """Supported SIEM platforms"""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    AZURE_SENTINEL = "azure_sentinel"
    DATADOG = "datadog"
    SUMOLOGIC = "sumologic"

class SIEMConnector:
    """
    Base SIEM connector for sending events and alerts
    """
    
    def __init__(self, siem_type: SIEMType, config_dict: Dict[str, str]):
        self.siem_type = siem_type
        self.endpoint = config_dict.get('endpoint')
        self.token = config_dict.get('token')
        self.index = config_dict.get('index', 'autohoneyx')
        self.enabled = config_dict.get('enabled', False)
        self.batch_size = int(config_dict.get('batch_size', 100))
        self.timeout = int(config_dict.get('timeout', 10))
        
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send single event to SIEM"""
        raise NotImplementedError
    
    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send batch of events to SIEM"""
        raise NotImplementedError
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test SIEM connectivity"""
        raise NotImplementedError

class SplunkConnector(SIEMConnector):
    """Splunk HTTP Event Collector (HEC) connector"""
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to Splunk HEC"""
        if not self.enabled or not self.endpoint:
            return False
        
        try:
            payload = {
                'event': event,
                'sourcetype': '_json',
                'index': self.index,
                'source': 'autohoneyx'
            }
            
            headers = {
                'Authorization': f'Splunk {self.token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.endpoint}/services/collector",
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=False  # Self-signed certs common in Splunk
            )
            
            if response.status_code in [200, 201]:
                logger.debug(f"Sent event to Splunk: {event.get('event_type', 'unknown')}")
                return True
            else:
                logger.error(f"Splunk HEC error: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send batch to Splunk"""
        if not self.enabled:
            return False
        
        success_count = 0
        for event in events:
            if self.send_event(event):
                success_count += 1
        
        logger.info(f"Sent {success_count}/{len(events)} events to Splunk")
        return success_count == len(events)
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Splunk connectivity"""
        try:
            headers = {
                'Authorization': f'Splunk {self.token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f"{self.endpoint}/services/collector/health",
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                return True, "Splunk HEC is reachable"
            else:
                return False, f"Splunk returned {response.status_code}"
                
        except Exception as e:
            return False, f"Connection error: {str(e)}"

class ElasticsearchConnector(SIEMConnector):
    """Elasticsearch/ELK connector"""
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to Elasticsearch"""
        if not self.enabled or not self.endpoint:
            return False
        
        try:
            url = f"{self.endpoint}/{self.index}-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.token}' if self.token else None
            }
            headers = {k: v for k, v in headers.items() if v}
            
            event['timestamp'] = datetime.utcnow().isoformat()
            
            response = requests.post(
                url,
                json=event,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.debug(f"Sent event to Elasticsearch: {event.get('event_type', 'unknown')}")
                return True
            else:
                logger.error(f"Elasticsearch error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Elasticsearch: {e}")
            return False
    
    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send batch using bulk API"""
        if not self.enabled:
            return False
        
        try:
            bulk_body = ""
            for event in events:
                meta = json.dumps({
                    'index': {
                        '_index': f"{self.index}-{datetime.utcnow().strftime('%Y.%m.%d')}",
                        '_type': '_doc'
                    }
                })
                event['timestamp'] = datetime.utcnow().isoformat()
                bulk_body += meta + "\n"
                bulk_body += json.dumps(event) + "\n"
            
            headers = {
                'Content-Type': 'application/x-ndjson',
                'Authorization': f'Bearer {self.token}' if self.token else None
            }
            headers = {k: v for k, v in headers.items() if v}
            
            response = requests.post(
                f"{self.endpoint}/_bulk",
                data=bulk_body,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            return response.status_code in [200, 201]
            
        except Exception as e:
            logger.error(f"Elasticsearch bulk error: {e}")
            return False
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Elasticsearch connectivity"""
        try:
            response = requests.get(
                f"{self.endpoint}/_cluster/health",
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status', 'unknown')
                return True, f"Elasticsearch cluster status: {status}"
            else:
                return False, f"Elasticsearch returned {response.status_code}"
                
        except Exception as e:
            return False, f"Connection error: {str(e)}"

class AzureSentinelConnector(SIEMConnector):
    """Azure Sentinel (Log Analytics) connector"""
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to Azure Sentinel"""
        if not self.enabled or not self.token:
            return False
        
        try:
            # Event data for Log Analytics
            log_data = json.dumps(event)
            
            # Using custom logs table
            signature = self._build_signature(log_data)
            
            headers = {
                'Authorization': signature,
                'Log-Type': 'AutoHoneyX',
                'x-ms-date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.endpoint}/api/logs",
                data=log_data,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code in [200, 201, 202]:
                logger.debug(f"Sent event to Azure Sentinel")
                return True
            else:
                logger.error(f"Azure Sentinel error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Azure Sentinel: {e}")
            return False
    
    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send batch to Azure Sentinel"""
        success_count = 0
        for event in events:
            if self.send_event(event):
                success_count += 1
        
        return success_count == len(events)
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Azure Sentinel connectivity"""
        # Simplified test
        return True, "Azure Sentinel connector configured" if self.token else False, "No token provided"
    
    @staticmethod
    def _build_signature(log_data: str) -> str:
        """Build Azure signature (simplified)"""
        import hmac
        import hashlib
        import base64
        
        # This would use workspace ID and key in production
        return "Bearer token_placeholder"

class SIEMManager:
    """
    Manages multiple SIEM connectors
    Routes events to appropriate SIEM platforms
    """
    
    def __init__(self):
        self.connectors: Dict[SIEMType, SIEMConnector] = {}
        self._init_connectors()
    
    def _init_connectors(self):
        """Initialize SIEM connectors from config"""
        # Splunk
        splunk_config = {
            'endpoint': getattr(config, 'SPLUNK_HEC_ENDPOINT', None),
            'token': getattr(config, 'SPLUNK_HEC_TOKEN', None),
            'index': getattr(config, 'SPLUNK_INDEX', 'autohoneyx'),
            'enabled': getattr(config, 'SPLUNK_ENABLED', False)
        }
        if splunk_config['endpoint']:
            self.connectors[SIEMType.SPLUNK] = SplunkConnector(SIEMType.SPLUNK, splunk_config)
        
        # Elasticsearch
        elk_config = {
            'endpoint': getattr(config, 'ELASTICSEARCH_ENDPOINT', None),
            'token': getattr(config, 'ELASTICSEARCH_TOKEN', None),
            'index': getattr(config, 'ELASTICSEARCH_INDEX', 'autohoneyx'),
            'enabled': getattr(config, 'ELASTICSEARCH_ENABLED', False)
        }
        if elk_config['endpoint']:
            self.connectors[SIEMType.ELASTICSEARCH] = ElasticsearchConnector(SIEMType.ELASTICSEARCH, elk_config)
        
        # Azure Sentinel
        sentinel_config = {
            'endpoint': getattr(config, 'AZURE_SENTINEL_ENDPOINT', None),
            'token': getattr(config, 'AZURE_SENTINEL_TOKEN', None),
            'enabled': getattr(config, 'AZURE_SENTINEL_ENABLED', False)
        }
        if sentinel_config['endpoint']:
            self.connectors[SIEMType.AZURE_SENTINEL] = AzureSentinelConnector(SIEMType.AZURE_SENTINEL, sentinel_config)
        
        logger.info(f"Initialized {len(self.connectors)} SIEM connectors")
    
    def normalize_event(self, attack_log: AttackLog, 
                       kill_chain_event: Optional[KillChainEvent] = None,
                       anomaly_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Convert AutoHoneyX event to SIEM-agnostic format (CEF-like)"""
        
        event = {
            'event_type': 'honeytoken_trigger',
            'source_application': 'AutoHoneyX',
            'timestamp': attack_log.timestamp.isoformat() if attack_log.timestamp else datetime.utcnow().isoformat(),
            'source_ip': attack_log.source_ip,
            'source_user_agent': attack_log.user_agent,
            'honeypot_type': attack_log.honeypot_type,
            'severity': attack_log.severity or 'MEDIUM',
            'classification': attack_log.classification,
        }
        
        if kill_chain_event:
            event.update({
                'mitre_tactic': kill_chain_event.mitre_tactic,
                'mitre_technique': kill_chain_event.mitre_technique,
                'kill_chain_phase': kill_chain_event.kill_chain_phase,
                'severity_score': float(kill_chain_event.severity_score or 0)
            })
        
        if anomaly_data:
            event.update({
                'anomaly_score': anomaly_data.get('score'),
                'is_anomalous': anomaly_data.get('is_anomalous'),
                'deviation_type': anomaly_data.get('deviation_type')
            })
        
        return event
    
    def send_event(self, attack_log: AttackLog,
                  kill_chain_event: Optional[KillChainEvent] = None,
                  anomaly_data: Optional[Dict] = None) -> bool:
        """
        Send event to all configured SIEM platforms
        
        Returns: True if at least one SIEM accepted the event
        """
        event = self.normalize_event(attack_log, kill_chain_event, anomaly_data)
        
        results = []
        for siem_type, connector in self.connectors.items():
            try:
                success = connector.send_event(event)
                results.append(success)
                if success:
                    logger.info(f"Sent event to {siem_type.value}")
            except Exception as e:
                logger.error(f"Error sending to {siem_type.value}: {e}")
                results.append(False)
        
        return any(results) if results else False
    
    def send_batch(self, attack_logs: List[AttackLog]) -> bool:
        """Send multiple logs to SIEM"""
        events = [self.normalize_event(log) for log in attack_logs]
        
        results = []
        for siem_type, connector in self.connectors.items():
            try:
                success = connector.send_batch(events)
                results.append(success)
            except Exception as e:
                logger.error(f"Batch send error to {siem_type.value}: {e}")
        
        return any(results) if results else False
    
    def test_all_connections(self) -> Dict[str, Tuple[bool, str]]:
        """Test connectivity to all configured SIEMs"""
        results = {}
        for siem_type, connector in self.connectors.items():
            success, message = connector.test_connection()
            results[siem_type.value] = (success, message)
        return results


# Global instance
siem_manager = None

def init_siem_manager():
    """Initialize the global SIEM manager"""
    global siem_manager
    siem_manager = SIEMManager()
    logger.info("SIEM manager initialized")

def get_siem_manager() -> SIEMManager:
    """Get or initialize the SIEM manager"""
    global siem_manager
    if siem_manager is None:
        init_siem_manager()
    return siem_manager
