# Add this entire class to the new file
import json
import os
from pathlib import Path

class ConfigManager:
    def __init__(self):
        self.config_file = Path("config/autohoneyx_config.json")
        self.config_file.parent.mkdir(exist_ok=True)
        
        self.config_schema = {
            'security': {
                'encryption_enabled': bool,
                'alert_thresholds': dict,
                'blacklist_auto_update': bool
            },
            'honeypots': {
                'adaptive_responses': bool,
                'rate_limiting': dict,
                'logging_level': str
            }
        }
        
        self.load_config()
    
    def load_config(self):
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.get_default_config()
            self.save_config()
    
    def get_default_config(self):
        return {
            'security': {
                'encryption_enabled': True,
                'alert_thresholds': {
                    'critical': 10,
                    'high': 25,
                    'medium': 50
                },
                'blacklist_auto_update': True
            },
            'honeypots': {
                'adaptive_responses': True,
                'rate_limiting': {
                    'max_requests_per_minute': 60,
                    'block_duration_minutes': 15
                },
                'logging_level': 'INFO'
            }
        }
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def validate_config(self, new_config):
        # Validate configuration changes
        try:
            # Basic validation - you can expand this
            if not isinstance(new_config.get('security', {}), dict):
                return False, "Security config must be a dictionary"
            return True, "Configuration is valid"
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def update_config(self, new_config):
        is_valid, message = self.validate_config(new_config)
        if not is_valid:
            return False, message
        
        self.config.update(new_config)
        self.save_config()
        return True, "Configuration updated successfully"