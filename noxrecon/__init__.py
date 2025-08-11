"""
NoxRecon - Advanced OSINT Reconnaissance Toolkit
Enhanced Edition v2.0.0

A professional-grade toolkit for Open Source Intelligence (OSINT) operations,
designed for Red Team professionals, penetration testers, and cybersecurity experts.

Features:
- WHOIS Lookup with structured output
- Advanced DNS enumeration
- Reverse IP resolution
- Subdomain discovery via Certificate Transparency
- Web technology detection and analysis
- IP geolocation with multiple sources
- Metadata extraction from files
- Interactive CLI with input validation
- Async operations for improved performance
- Professional error handling and logging

Author: NoxRecon Team (@Ismaeldevs)
License: MIT
GitHub: https://github.com/Ismaeldevs/NoxRecon
"""

__version__ = "2.0.0"
__author__ = "NoxRecon Team"
__email__ = "contact@noxrecon.dev"
__license__ = "MIT"
__copyright__ = "Copyright 2024 NoxRecon Team"

# Package metadata
__title__ = "noxrecon"
__description__ = "Advanced OSINT Reconnaissance Toolkit for Cybersecurity Professionals"
__url__ = "https://github.com/Ismaeldevs/NoxRecon"
__status__ = "Production"
__keywords__ = ["osint", "reconnaissance", "pentesting", "cybersecurity", "red-team"]

# Import main components for easy access
from . import core
from . import utils
from . import validators
from . import menu

# Export main functions
__all__ = [
    'core',
    'utils', 
    'validators',
    'menu',
    '__version__',
    '__author__',
    '__description__'
]

# Version info tuple
VERSION_INFO = tuple(map(int, __version__.split('.')))

def get_version():
    """Return the version string"""
    return __version__

def get_author():
    """Return the author information"""
    return __author__

def main():
    """Main entry point for the application"""
    from .menu import main_menu
    main_menu()
