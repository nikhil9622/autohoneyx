# Add this entire class to the new file
class AdaptiveHoneypot:
# OLD_AWS_ACCESS_KEY_ID=AKIAQDRB59HKEMLWS4SX
# OLD_AWS_SECRET_ACCESS_KEY=ojh5C=EpH3+5XCftCW4kt0THK8mKFrjEDeC2FftC
    def __init__(self):
        self.threat_levels = {
            'recon': ['nmap', 'masscan', 'nikto'],
            'exploit': ['metasploit', 'sqlmap', 'burp'],
            'lateral': ['psexec', 'smbclient', 'ssh']
        }
    
    def detect_threat_level(self, request):
        # Analyze user-agent, request patterns, timing
        if any(tool in request.user_agent for tool in self.threat_levels['exploit']):
            return 'HIGH'
        return 'NORMAL'
    
    def respond_adaptively(self, threat_level):
        # Slow responses for recon, detailed logs for exploits
        delays = {'LOW': 0.1, 'NORMAL': 1, 'HIGH': 5}
        return delays.get(threat_level, 1)