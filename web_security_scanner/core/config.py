"""
Configuration management for Web Security Scanner
Handles YAML configuration files and default settings
"""

import yaml
import os
from typing import Dict, Any
from pathlib import Path


class Config:
    """Manages configuration for the scanner"""
    
    DEFAULT_CONFIG = {
        'scanner': {
            'threads': 10,
            'timeout': 35,
            'max_depth': 3,
            'follow_redirects': True,
            'verify_ssl': False,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'rate_limit': 10,  # requests per second
            'max_retries': 3,
            'retry_delay': 2
        },
        'cache': {
            'enabled': True,
            'max_size': 1000,
            'ttl': 3600  # seconds
        },
        'vulnerabilities': {
            'sql_injection': {
                'enabled': True,
                'severity': 'critical',
                'max_payloads': 50
            },
            'xss': {
                'enabled': True,
                'severity': 'high',
                'max_payloads': 50
            },
            'nosql_injection': {
                'enabled': True,
                'severity': 'critical',
                'max_payloads': 50
            },
            'open_redirect': {
                'enabled': True,
                'severity': 'medium',
                'max_payloads': 20
            },
            'ssrf': {
                'enabled': True,
                'severity': 'critical',
                'max_payloads': 30
            },
            'csrf': {
                'enabled': True,
                'severity': 'high',
                'max_payloads': 10
            },
            'xxe': {
                'enabled': True,
                'severity': 'critical',
                'max_payloads': 20
            },
            'command_injection': {
                'enabled': True,
                'severity': 'critical',
                'max_payloads': 40
            },
            'path_traversal': {
                'enabled': True,
                'severity': 'high',
                'max_payloads': 30
            },
            'idor': {
                'enabled': True,
                'severity': 'high',
                'max_payloads': 15
            }
        },
        'technology_detection': {
            'enabled': True,
            'analyze_headers': True,
            'analyze_html': True,
            'analyze_scripts': True,
            'analyze_cookies': True,
            'fingerprint_cms': True
        },
        'reporting': {
            'formats': ['json', 'html', 'pdf'],
            'output_dir': 'reports',
            'include_screenshots': False,
            'detailed_mode': True
        },
        'database': {
            'enabled': True,
            'path': 'scans.db',
            'keep_history': True,
            'max_history_days': 90
        },
        'authentication': {
            'enabled': False,
            'type': None,  # 'basic', 'bearer', 'session', 'oauth'
            'credentials': {}
        },
        'logging': {
            'level': 'INFO',
            'file': 'scanner.log',
            'max_size': 10485760,  # 10MB
            'backup_count': 5,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    }
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration
        
        Args:
            config_file: Path to YAML config file (optional)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
    
    def load_from_file(self, config_file: str):
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    self._merge_config(self.config, user_config)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated path
        
        Example: config.get('scanner.threads')
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any):
        """Set configuration value by dot-separated path"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def save_to_file(self, config_file: str):
        """Save current configuration to YAML file"""
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            print(f"Error saving config file: {e}")
    
    def get_scan_profile(self, profile: str) -> Dict[str, Any]:
        """
        Get predefined scan profile
        
        Args:
            profile: 'quick', 'normal', 'deep', 'stealth'
        """
        profiles = {
            'quick': {
                'threads': 20,
                'timeout': 10,
                'max_depth': 2,
                'max_payloads_multiplier': 0.3
            },
            'normal': {
                'threads': 10,
                'timeout': 35,
                'max_depth': 3,
                'max_payloads_multiplier': 1.0
            },
            'deep': {
                'threads': 5,
                'timeout': 60,
                'max_depth': 5,
                'max_payloads_multiplier': 2.0
            },
            'stealth': {
                'threads': 2,
                'timeout': 45,
                'max_depth': 3,
                'max_payloads_multiplier': 1.0,
                'rate_limit': 2
            }
        }
        
        return profiles.get(profile, profiles['normal'])
    
    def apply_profile(self, profile: str):
        """Apply a scan profile to the current configuration"""
        profile_config = self.get_scan_profile(profile)
        
        for key, value in profile_config.items():
            if key == 'max_payloads_multiplier':
                # Apply multiplier to all vulnerability max_payloads
                for vuln in self.config['vulnerabilities'].values():
                    if 'max_payloads' in vuln:
                        vuln['max_payloads'] = int(vuln['max_payloads'] * value)
            else:
                self.set(f'scanner.{key}', value)
