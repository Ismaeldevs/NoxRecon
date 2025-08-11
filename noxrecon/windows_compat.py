"""
Windows-specific adaptations for NoxRecon
Provides fallback implementations for missing Unix tools
"""
import socket
import subprocess
import json
import requests
from typing import Optional, Dict, Any
import concurrent.futures
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure requests session with retries for Windows compatibility
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

"""
Windows-specific adaptations for NoxRecon
Provides fallback implementations for missing Unix tools
"""
import socket
import subprocess
import json
import requests
from typing import Optional, Dict, Any
import concurrent.futures
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure requests session with retries for Windows compatibility
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def get_utils_functions():
    """Lazy import of utils functions to avoid circular imports"""
    from .utils import print_info, print_success, print_warning, print_error, print_result_table
    return print_info, print_success, print_warning, print_error, print_result_table

def windows_whois_lookup(target: str) -> Optional[str]:
    """Windows-compatible WHOIS lookup using Python libraries"""
    print_info, print_success, print_warning, print_error, print_result_table = get_utils_functions()
    
    try:
        # Try using nslookup as a fallback (available on Windows)
        result = subprocess.run(
            ["nslookup", target],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
        
        # Fallback: Use online WHOIS API
        return online_whois_lookup(target)
        
    except Exception as e:
        print_warning(f"Windows WHOIS fallback failed: {str(e)}")
        return None

def online_whois_lookup(domain: str) -> Optional[str]:
    """Online WHOIS lookup using web APIs"""
    print_info, print_success, print_warning, print_error, print_result_table = get_utils_functions()
    
    try:
        # Clean domain for API
        if '://' in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        
        # Try whois.io API (free tier available)
        url = f"https://whois.io/whois/{domain}"
        headers = {'User-Agent': 'NoxRecon/2.0.0 (OSINT Toolkit)'}
        
        response = session.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        
        # Fallback: Try ipinfo.io for basic domain info
        url = f"https://ipinfo.io/{domain}/json"
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return f"Domain: {domain}\nOrganization: {data.get('org', 'Unknown')}\nCountry: {data.get('country', 'Unknown')}"
        
        return None
        
    except Exception as e:
        print_warning(f"Online WHOIS lookup failed: {str(e)}")
        return None

def windows_dns_lookup(domain: str) -> Dict[str, Any]:
    """Windows-compatible DNS lookup using dnspython"""
    import dns.resolver
    
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = []
            
            for answer in answers:
                if record_type == 'MX':
                    records.append(f"{answer.preference} {answer.exchange}")
                else:
                    records.append(str(answer))
            
            if records:
                results[f"{record_type} Records"] = records
                
        except dns.resolver.NXDOMAIN:
            results[f"{record_type} Records"] = ["Domain does not exist"]
        except dns.resolver.NoAnswer:
            continue  # Skip if no records of this type
        except Exception as e:
            results[f"{record_type} Records"] = [f"Query failed: {str(e)}"]
    
    return results

def windows_reverse_lookup(target: str) -> Dict[str, str]:
    """Windows-compatible reverse lookup"""
    result = {}
    
    try:
        # If target is domain, resolve to IP first
        if not target.replace('.', '').replace(':', '').isdigit():
            ip = socket.gethostbyname(target)
            result['Resolved IP'] = ip
            target = ip
        
        # Perform reverse lookup
        try:
            hostname = socket.gethostbyaddr(target)[0]
            result['Hostname'] = hostname
            result['Status'] = 'Success'
        except socket.herror:
            result['Hostname'] = 'No reverse DNS record'
            result['Status'] = 'No PTR record found'
        
        result['IP Address'] = target
        
    except Exception as e:
        result['Error'] = str(e)
        result['Status'] = 'Failed'
    
    return result

def windows_curl_alternative(url: str, json_output: bool = False) -> Optional[str]:
    """Alternative to curl command using requests"""
    print_info, print_success, print_warning, print_error, print_result_table = get_utils_functions()
    
    try:
        headers = {
            'User-Agent': 'NoxRecon/2.0.0 (OSINT Toolkit)',
            'Accept': 'application/json' if json_output else 'text/html'
        }
        
        response = session.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.text
        else:
            print_warning(f"HTTP {response.status_code}: {response.reason}")
            return None
            
    except Exception as e:
        print_error(f"Request failed: {str(e)}")
        return None

def windows_subdomains_crtsh(domain: str) -> list:
    """Windows-compatible subdomain enumeration"""
    print_info, print_success, print_warning, print_error, print_result_table = get_utils_functions()
    
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        print_info(f"Querying Certificate Transparency logs for {domain}...")
        response = session.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    domains = name_value.split('\n')
                    for sub in domains:
                        sub = sub.strip()
                        if sub and domain in sub:
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            subdomains.add(sub.lower())
            
            return sorted(list(subdomains))
        else:
            print_error(f"crt.sh query failed with status: {response.status_code}")
            return []
            
    except Exception as e:
        print_error(f"Subdomain enumeration failed: {str(e)}")
        return []

def windows_basic_tech_detection(url: str) -> Dict[str, str]:
    """Basic web technology detection without WhatWeb"""
    print_info, print_success, print_warning, print_error, print_result_table = get_utils_functions()
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        print_info(f"Performing basic technology analysis for {url}...")
        response = session.get(url, timeout=10)
        
        headers = response.headers
        content = response.text.lower()
        
        tech_info = {
            'HTTP Status': str(response.status_code),
            'Server': headers.get('Server', 'Not disclosed'),
            'X-Powered-By': headers.get('X-Powered-By', 'Not disclosed'),
            'Content-Type': headers.get('Content-Type', 'Unknown'),
        }
        
        # Content-based detection
        if 'wordpress' in content or 'wp-content' in content:
            tech_info['CMS'] = 'WordPress'
        elif 'drupal' in content:
            tech_info['CMS'] = 'Drupal'
        elif 'joomla' in content:
            tech_info['CMS'] = 'Joomla'
        elif 'shopify' in content:
            tech_info['Platform'] = 'Shopify'
        
        # Framework detection
        if 'react' in content:
            tech_info['Frontend'] = 'React'
        elif 'angular' in content:
            tech_info['Frontend'] = 'Angular'
        elif 'vue' in content:
            tech_info['Frontend'] = 'Vue.js'
        
        # Remove entries with 'Not disclosed' or 'Unknown'
        tech_info = {k: v for k, v in tech_info.items() 
                    if v not in ['Not disclosed', 'Unknown', '']}
        
        return tech_info
        
    except Exception as e:
        print_error(f"Technology detection failed: {str(e)}")
        return {'Error': str(e)}

def windows_check_live_domains(domains: list, max_workers: int = 5) -> list:
    """Check which domains are live using threading"""
    live_domains = []
    
    def check_domain(domain):
        for protocol in ['https', 'http']:
            try:
                response = session.get(f"{protocol}://{domain}", timeout=5)
                if response.status_code < 400:
                    return domain
            except:
                continue
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain 
                           for domain in domains[:20]}  # Limit to first 20
        
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            if result:
                live_domains.append(result)
    
    return live_domains

def check_windows_compatibility():
    """Check what Windows-compatible features are available"""
    compatibility = {
        'Python DNS': True,  # dnspython is installed
        'HTTP Requests': True,  # requests is installed
        'Socket Operations': True,  # Built-in socket module
        'Subprocess': True,  # Built-in subprocess module
    }
    
    # Check for optional Windows tools
    try:
        subprocess.run(["nslookup"], capture_output=True, timeout=1)
        compatibility['nslookup'] = True
    except:
        compatibility['nslookup'] = False
    
    try:
        subprocess.run(["powershell", "-Command", "Get-Host"], capture_output=True, timeout=2)
        compatibility['PowerShell'] = True
    except:
        compatibility['PowerShell'] = False
    
    return compatibility

def get_windows_system_info():
    """Get Windows-specific system information"""
    import platform
    
    info = {
        'Operating System': f"{platform.system()} {platform.release()}",
        'Architecture': platform.machine(),
        'Python Version': platform.python_version(),
        'Python Executable': str(Path(platform.sys.executable)),
        'Working Directory': str(Path.cwd()),
        'Windows Version': platform.version(),
    }
    
    try:
        # Get PowerShell version if available
        result = subprocess.run(
            ["powershell", "-Command", "$PSVersionTable.PSVersion"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            info['PowerShell Version'] = result.stdout.strip()
    except:
        info['PowerShell Version'] = 'Not available'
    
    return info
