"""
Configuration module for NoxRecon
Handles settings, preferences, and configuration management
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    "general": {
        "timeout": 30,
        "max_retries": 3,
        "user_agent": "NoxRecon/2.0.0 (OSINT Toolkit)",
        "rate_limit_delay": 1.0,
        "max_concurrent_requests": 5,
        "output_format": "table",  # table, json, csv
        "save_results": False,
        "results_directory": "noxrecon_results"
    },
    "dns": {
        "nameservers": ["8.8.8.8", "1.1.1.1"],
        "record_types": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
        "timeout": 10
    },
    "subdomains": {
        "sources": ["crt.sh"],
        "check_live": True,
        "max_subdomains_to_check": 50,
        "live_check_timeout": 5
    },
    "geolocation": {
        "services": ["ipinfo.io", "ip-api.com"],
        "fallback_enabled": True
    },
    "whatweb": {
        "aggressive_mode": False,
        "follow_redirects": True,
        "max_redirects": 3
    },
    "metadata": {
        "max_file_size_mb": 100,
        "extract_thumbnails": False,
        "show_warnings": True
    },
    "ui": {
        "style": "professional",  # professional, hacker, minimal
        "animations": True,
        "progress_bars": True,
        "color_output": True,
        "clear_screen": True
    }
}

class Config:
    """Configuration manager for NoxRecon"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".noxrecon"
        self.config_file = self.config_dir / "config.json"
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    self._merge_config(self.config, user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config file: {e}")
    
    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            self.config_dir.mkdir(exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except IOError as e:
            print(f"Error: Could not save config file: {e}")
            return False
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.config.get(section, {})
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults"""
        self.config = DEFAULT_CONFIG.copy()
    
    def _merge_config(self, base: Dict, override: Dict) -> None:
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

# Global configuration instance
config = Config()

# Convenience functions
def get_timeout() -> int:
    """Get default timeout value"""
    return config.get("general", "timeout", 30)

def get_user_agent() -> str:
    """Get user agent string"""
    return config.get("general", "user_agent", "NoxRecon/2.0.0")

def get_nameservers() -> list:
    """Get DNS nameservers"""
    return config.get("dns", "nameservers", ["8.8.8.8", "1.1.1.1"])

def get_rate_limit_delay() -> float:
    """Get rate limiting delay"""
    return config.get("general", "rate_limit_delay", 1.0)

def is_save_results_enabled() -> bool:
    """Check if result saving is enabled"""
    return config.get("general", "save_results", False)

def get_results_directory() -> str:
    """Get results directory path"""
    return config.get("general", "results_directory", "noxrecon_results")

def should_check_live_subdomains() -> bool:
    """Check if live subdomain checking is enabled"""
    return config.get("subdomains", "check_live", True)

def get_max_subdomains_to_check() -> int:
    """Get maximum number of subdomains to check for liveness"""
    return config.get("subdomains", "max_subdomains_to_check", 50)

def get_geolocation_services() -> list:
    """Get list of geolocation services"""
    return config.get("geolocation", "services", ["ipinfo.io", "ip-api.com"])

def is_animations_enabled() -> bool:
    """Check if UI animations are enabled"""
    return config.get("ui", "animations", True)

def is_progress_bars_enabled() -> bool:
    """Check if progress bars are enabled"""
    return config.get("ui", "progress_bars", True)

def get_max_file_size_mb() -> int:
    """Get maximum file size for metadata extraction"""
    return config.get("metadata", "max_file_size_mb", 100)
