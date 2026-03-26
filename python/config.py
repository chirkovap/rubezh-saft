#!/usr/bin/env python3
"""
XDPGuard Configuration Manager

Handles loading and managing YAML configuration.
"""

import secrets
import yaml
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for XDPGuard"""

    def __init__(self, config_path: str = "/etc/xdpguard/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load()

    def load(self) -> dict:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            logger.error(f"Config file not found: {self.config_path}")
            return self._default_config()

        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Configuration loaded from {self.config_path}")
                return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._default_config()

    def save(self) -> bool:
        """Save current configuration to YAML file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
                logger.info(f"Configuration saved to {self.config_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

    def get(self, path: str, default: Any = None) -> Any:
        """Get configuration value by dot notation path
        
        Example: config.get('network.interface', 'eth0')
        """
        keys = path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
                
        return value

    def set(self, path: str, value: Any) -> bool:
        """Set configuration value by dot notation path"""
        keys = path.split('.')
        target = self.config
        
        for key in keys[:-1]:
            target = target.setdefault(key, {})
            
        target[keys[-1]] = value
        return True

    def _default_config(self) -> dict:
        """Return default configuration"""
        return {
            'network': {
                'interface': 'eth0',
                'mode': 'router',
                'protected_ports': [80, 443, 22]
            },
            'protection': {
                'enabled': True,
                'syn_rate': 30,
                'syn_burst': 50,
                'whitelist_ips': ['127.0.0.0/8', '10.0.0.0/8']
            },
            'web': {
                'host': '127.0.0.1',  # Bind to localhost only; set to 0.0.0.0 (with firewall rules) to allow remote access
                'port': 8080,
                # Generated at runtime so every installation that falls back to
                # the default config gets a unique, unpredictable key.
                'secret_key': secrets.token_hex(32)
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/xdpguard.log'
            }
        }

    def validate(self) -> bool:
        """Validate configuration"""
        required_keys = ['network', 'protection', 'web', 'logging']
        
        for key in required_keys:
            if key not in self.config:
                logger.error(f"Missing required config section: {key}")
                return False
                
        return True

    def reload(self) -> bool:
        """Reload configuration from file"""
        self.config = self.load()
        return self.validate()
