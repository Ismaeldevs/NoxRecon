"""
Validation utilities for NoxRecon
"""
import re
import socket
import validators as val
from urllib.parse import urlparse
from .utils import print_error, print_warning

def is_valid_ip(ip):
    """Validate if string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_domain(domain):
    """Validate if string is a valid domain name"""
    # Remove protocol if present
    if '://' in domain:
        domain = urlparse(domain).netloc or urlparse(domain).path
    
    # Basic domain regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(domain)) and len(domain) <= 253

def is_valid_url(url):
    """Validate if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_file_path(file_path):
    """Basic file path validation"""
    import os
    return os.path.exists(file_path) and os.path.isfile(file_path)

def validate_target(target, target_type="domain"):
    """
    Validate target based on type
    Returns (is_valid, cleaned_target, error_msg)
    """
    if not target or not target.strip():
        return False, "", "Target cannot be empty"
    
    target = target.strip()
    
    if target_type == "domain":
        if is_valid_domain(target):
            return True, target, ""
        elif is_valid_ip(target):
            return True, target, ""
        else:
            return False, target, "Invalid domain or IP address format"
    
    elif target_type == "ip":
        if is_valid_ip(target):
            return True, target, ""
        else:
            return False, target, "Invalid IP address format"
    
    elif target_type == "url":
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        if is_valid_url(target):
            return True, target, ""
        else:
            return False, target, "Invalid URL format"
    
    elif target_type == "file":
        if is_valid_file_path(target):
            return True, target, ""
        else:
            return False, target, "File not found or is not a valid file"
    
    return True, target, ""  # Default: accept anything

def sanitize_domain(domain):
    """Clean and sanitize domain input"""
    if not domain:
        return ""
    
    # Remove common protocols
    domain = domain.replace('http://', '').replace('https://', '')
    domain = domain.replace('www.', '')
    
    # Remove trailing slash and path
    domain = domain.split('/')[0]
    
    # Remove port if present
    domain = domain.split(':')[0]
    
    return domain.lower().strip()

def prompt_with_validation(prompt_text, target_type="domain", allow_empty=False):
    """
    Prompt user for input with validation
    Returns validated input or None if cancelled
    """
    from .utils import CYAN, YELLOW, RESET
    
    while True:
        try:
            user_input = input(f"{CYAN}{prompt_text}{RESET}").strip()
            
            if not user_input and allow_empty:
                return ""
            
            if not user_input:
                print_warning("Input cannot be empty. Try again or press Ctrl+C to cancel.")
                continue
            
            is_valid, cleaned_input, error_msg = validate_target(user_input, target_type)
            
            if is_valid:
                return cleaned_input
            else:
                print_error(f"Invalid input: {error_msg}")
                continue
                
        except KeyboardInterrupt:
            print_warning("\nOperation cancelled by user.")
            return None
        except EOFError:
            print_warning("\nOperation cancelled.")
            return None
