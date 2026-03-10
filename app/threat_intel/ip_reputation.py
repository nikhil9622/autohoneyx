"""
Threat Intelligence Integration
Checks IP reputation against multiple threat intelligence sources:
- AbuseIPDB (malicious IP database)
- VirusTotal (malware detection)
"""

import requests
import os
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Multi-source threat intelligence engine for IP reputation analysis
    """
    
    def __init__(self):
        self.abuseipdb_api = os.getenv("ABUSEIPDB_API_KEY", "demo-key")
        self.virustotal_api = os.getenv("VIRUSTOTAL_API_KEY", "demo-key")
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.virustotal_url = "https://www.virustotal.com/api/v3"
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """
        Check IP against multiple threat intel sources
        
        Args:
            ip_address: IP address to check
        
        Returns:
            Dictionary with reputation scores and risk assessment
        """
        
        try:
            # Check AbuseIPDB
            abuseipdb_score = self._check_abuseipdb(ip_address)
            
            # Check VirusTotal
            vt_detections = self._check_virustotal(ip_address)
            
            # Determine if IP is malicious
            is_malicious = False
            if abuseipdb_score and abuseipdb_score > 75:
                is_malicious = True
            if vt_detections and vt_detections.get('malicious', 0) > 5:
                is_malicious = True
            
            return {
                'ip': ip_address,
                'abuseipdb_score': abuseipdb_score,
                'virustotal_detections': vt_detections,
                'is_malicious': is_malicious,
                'risk_level': 'CRITICAL' if is_malicious else 'LOW',
                'timestamp': __import__('datetime').datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error checking IP reputation: {e}")
            return {
                'ip': ip_address,
                'error': str(e),
                'risk_level': 'UNKNOWN'
            }
    
    def _check_abuseipdb(self, ip_address: str) -> Optional[int]:
        """
        Query AbuseIPDB for malicious IP reputation
        Returns abuse confidence score (0-100)
        """
        try:
            if self.abuseipdb_api == "demo-key":
                # Return mock data for demo
                logger.warning("Using demo AbuseIPDB key - set ABUSEIPDB_API_KEY for real data")
                return 25  # Mock score
            
            headers = {
                'Key': self.abuseipdb_api,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return data['data']['abuseConfidenceScore']
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            return None
    
    def _check_virustotal(self, ip_address: str) -> Optional[Dict]:
        """
        Query VirusTotal for IP reputation
        Returns detection counts from security vendors
        """
        try:
            if self.virustotal_api == "demo-key":
                # Return mock data for demo
                logger.warning("Using demo VirusTotal key - set VIRUSTOTAL_API_KEY for real data")
                return {
                    'malicious': 2,
                    'suspicious': 1,
                    'detections': 3
                }
            
            headers = {
                'x-apikey': self.virustotal_api
            }
            
            response = requests.get(
                f'{self.virustotal_url}/ip_addresses/{ip_address}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                last_analysis = data['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': last_analysis['malicious'],
                    'suspicious': last_analysis['suspicious'],
                    'undetected': last_analysis['undetected'],
                    'detections': last_analysis['malicious'] + last_analysis['suspicious']
                }
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return None
    
    def get_geolocation(self, ip_address: str) -> Optional[Dict]:
        """
        Get geolocation and VPN/Proxy detection for IP
        Uses free GeoIP service (ip-api.com or similar)
        """
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5,
                params={'fields': 'status,country,city,isp,mobile,proxy,hosting'}
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'is_vpn': data.get('proxy', False),
                    'is_mobile': data.get('mobile', False),
                    'is_hosting': data.get('hosting', False)
                }
            return None
            
        except Exception as e:
            logger.error(f"Geolocation check failed: {e}")
            return None
