"""
Enhanced core functionality for NoxRecon
Includes improved error handling, async operations, and better output formatting
Cross-platform compatibility with Windows fallbacks
"""
import asyncio
import json
import re
import socket
import subprocess
import time
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import aiohttp
import dns.resolver
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .utils import (
    run_command, print_info, print_success, print_warning, print_error,
    print_result_header, print_result_table, format_json_output,
    create_progress_bar, console, CYAN, MAGENTA, RED, GREEN, YELLOW, RESET
)
from .validators import validate_target, sanitize_domain

# Import Windows compatibility functions
if sys.platform.startswith('win'):
    from .windows_compat import (
        windows_whois_lookup, windows_dns_lookup, windows_reverse_lookup,
        windows_subdomains_crtsh, windows_basic_tech_detection,
        windows_curl_alternative, windows_check_live_domains
    )

# Configure requests session with retries
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def whois_lookup(target):
    """Enhanced WHOIS lookup with validation and better output"""
    print_result_header("🔍 WHOIS Lookup", f"Target: {target}")
    
    # Validate target
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Performing WHOIS lookup for: [bold cyan]{target}[/bold cyan]")
    
    try:
        output = None
        
        # Check if we're on Windows and whois command is not available
        if sys.platform.startswith('win') and not shutil.which('whois'):
            print_info("Using Windows-compatible WHOIS lookup...")
            output = windows_whois_lookup(target)
        else:
            # Try standard WHOIS commands for Unix-like systems
            commands = [
                f"whois {target}",
                f"whois -h whois.iana.org {target}",
            ]
            
            for cmd in commands:
                output = run_command(cmd, timeout=15)
                if output and len(output) > 50:  # Valid WHOIS response
                    break
        
        if output:
            # Parse and format WHOIS data
            whois_data = parse_whois_output(output)
            if whois_data:
                print_result_table(whois_data, f"WHOIS Information for {target}")
            else:
                # Fallback to raw output
                console.print("\n[cyan]Raw WHOIS Output:[/cyan]")
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('%'):
                        console.print(f"  {line}")
            
            print_success(f"WHOIS lookup completed for {target}")
        else:
            print_warning(f"No WHOIS information found for {target}")
            
    except Exception as e:
        print_error(f"WHOIS lookup failed: {str(e)}")

def parse_whois_output(output):
    """Parse WHOIS output into structured data"""
    data = {}
    important_fields = {
        'Domain Name': ['domain name', 'domain'],
        'Registrar': ['registrar'],
        'Creation Date': ['creation date', 'created', 'registered'],
        'Expiration Date': ['expiration date', 'expires', 'expiry date'],
        'Updated Date': ['updated date', 'last updated', 'modified'],
        'Status': ['status', 'domain status'],
        'Name Servers': ['name server', 'nserver'],
        'Registrant': ['registrant', 'registrant name'],
        'Admin Contact': ['admin', 'administrative contact'],
        'Tech Contact': ['tech', 'technical contact']
    }
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if ':' in line and not line.startswith('%'):
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if value:  # Only add non-empty values
                for display_key, patterns in important_fields.items():
                    if any(pattern in key for pattern in patterns):
                        if display_key in data:
                            if isinstance(data[display_key], list):
                                data[display_key].append(value)
                            else:
                                data[display_key] = [data[display_key], value]
                        else:
                            data[display_key] = value
                        break
    
    return data

def dns_lookup(target):
    """Enhanced DNS lookup with multiple record types and better formatting"""
    print_result_header("🌐 DNS Lookup", f"Target: {target}")
    
    # Validate and clean target
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = sanitize_domain(clean_target)
    print_info(f"Performing DNS lookup for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # Use Windows-compatible DNS lookup if on Windows
        if sys.platform.startswith('win'):
            dns_results = windows_dns_lookup(target)
        else:
            # Use standard DNS resolution for Unix-like systems
            dns_results = unix_dns_lookup(target)
        
        if dns_results:
            print_result_table(dns_results, f"DNS Records for {target}")
            print_success(f"DNS lookup completed for {target}")
        else:
            print_warning(f"No DNS records found for {target}")
            
    except Exception as e:
        print_error(f"DNS lookup failed: {str(e)}")

def unix_dns_lookup(target):
    """Unix-style DNS lookup using dig command"""
    record_types = {
        'A': 'IPv4 Address',
        'AAAA': 'IPv6 Address', 
        'MX': 'Mail Exchange',
        'NS': 'Name Servers',
        'TXT': 'Text Records',
        'CNAME': 'Canonical Name',
        'SOA': 'Start of Authority'
    }
    
    dns_results = {}
    
    with create_progress_bar("DNS Lookup") as progress:
        task = progress.add_task("Querying DNS records...", total=len(record_types))
        
        for record_type, description in record_types.items():
            try:
                # Use dnspython for more reliable DNS queries
                answers = dns.resolver.resolve(target, record_type)
                results = []
                
                for answer in answers:
                    if record_type == 'MX':
                        results.append(f"{answer.preference} {answer.exchange}")
                    elif record_type == 'SOA':
                        results.append(f"Primary: {answer.mname}, Email: {answer.rname}")
                    else:
                        results.append(str(answer))
                
                if results:
                    dns_results[f"{record_type} ({description})"] = results
                    
            except dns.resolver.NXDOMAIN:
                dns_results[f"{record_type} ({description})"] = ["Domain does not exist"]
            except dns.resolver.NoAnswer:
                dns_results[f"{record_type} ({description})"] = ["No records found"]
            except Exception as e:
                dns_results[f"{record_type} ({description})"] = [f"Query failed: {str(e)}"]
            
            progress.advance(task)
    
    return dns_results

def reverse_ip_lookup(target):
    """Enhanced reverse IP lookup with geolocation"""
    print_result_header("🔄 Reverse IP Lookup", f"Target: {target}")
    
    # Validate IP or domain
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Performing reverse lookup for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # Use Windows-compatible reverse lookup if on Windows
        if sys.platform.startswith('win'):
            result = windows_reverse_lookup(target)
        else:
            result = unix_reverse_lookup(target)
        
        if result:
            print_result_table(result, f"Reverse Lookup for {target}")
            print_success(f"Reverse lookup completed for {target}")
        else:
            print_warning(f"Reverse lookup failed for {target}")
        
    except Exception as e:
        print_error(f"Reverse lookup failed: {str(e)}")

def unix_reverse_lookup(target):
    """Unix-style reverse lookup"""
    try:
        # If target is a domain, resolve to IP first
        if not target.replace('.', '').isdigit():
            try:
                ip = socket.gethostbyname(target)
                print_info(f"Resolved {target} to IP: {ip}")
                target = ip
            except socket.gaierror:
                print_error(f"Could not resolve domain: {target}")
                return None
        
        # Perform reverse lookup
        try:
            hostname = socket.gethostbyaddr(target)[0]
            result = {
                'IP Address': target,
                'Hostname': hostname,
                'Status': 'Reverse lookup successful'
            }
        except socket.herror:
            result = {
                'IP Address': target,
                'Hostname': 'No reverse DNS record',
                'Status': 'No PTR record found'
            }
        
        # Try to get additional info using dig command
        ptr_output = run_command(f"dig -x {target} +short", show_progress=False)
        if ptr_output and ptr_output != result.get('Hostname', ''):
            result['PTR Record'] = ptr_output
        
        return result
        
    except Exception as e:
        print_error(f"Unix reverse lookup failed: {str(e)}")
        return None

def subdomains_crtsh(domain):
    """Enhanced subdomain enumeration using crt.sh with cross-platform support"""
    print_result_header("🔍 Subdomain Enumeration", f"Domain: {domain}")
    
    # Validate domain
    is_valid, clean_domain, error_msg = validate_target(domain, "domain")
    if not is_valid:
        print_error(f"Invalid domain: {error_msg}")
        return
    
    domain = sanitize_domain(clean_domain)
    print_info(f"Searching subdomains for: [bold cyan]{domain}[/bold cyan]")
    
    try:
        # Use Windows-compatible subdomain search
        if sys.platform.startswith('win'):
            subdomains = windows_subdomains_crtsh(domain)
        else:
            subdomains = unix_subdomains_crtsh(domain)
        
        if subdomains:
            # Create table data
            table_data = []
            for i, subdomain in enumerate(subdomains, 1):
                table_data.append({
                    '#': i,
                    'Subdomain': subdomain,
                    'Type': 'Certificate Log'
                })
            
            print_result_table(table_data, f"Subdomains found for {domain} ({len(subdomains)} total)")
            print_success(f"Found {len(subdomains)} unique subdomains")
            
            # Optional: Check which subdomains are live
            if len(subdomains) <= 20:  # Only for small lists
                check_live_subdomains(subdomains[:10])  # Check first 10
        else:
            print_warning(f"No subdomains found for {domain}")
            
    except Exception as e:
        print_error(f"Subdomain enumeration failed: {str(e)}")

def unix_subdomains_crtsh(domain):
    """Unix-style subdomain enumeration using curl"""
    try:
        # Use requests instead of curl for better error handling
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        with create_progress_bar("Subdomain Search") as progress:
            task = progress.add_task("Querying crt.sh...", total=None)
            
            response = session.get(url, timeout=30)
            progress.update(task, completed=True)
        
        if response.status_code == 200:
            try:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple domains in one entry
                        domains = name_value.split('\n')
                        for sub in domains:
                            sub = sub.strip()
                            if sub and domain in sub:
                                # Clean wildcard entries
                                if sub.startswith('*.'):
                                    sub = sub[2:]
                                subdomains.add(sub.lower())
                
                return sorted(list(subdomains))
                
            except json.JSONDecodeError:
                print_error("Failed to parse JSON response from crt.sh")
                return []
        else:
            print_error(f"crt.sh query failed with status: {response.status_code}")
            return []
            
    except Exception as e:
        print_error(f"Unix subdomain enumeration failed: {str(e)}")
        return []

def check_live_subdomains(subdomains):
    """Check if subdomains are live (cross-platform)"""
    print_info("Checking live status for top subdomains...")
    
    if sys.platform.startswith('win'):
        live_domains = windows_check_live_domains(subdomains)
    else:
        live_domains = unix_check_live_domains(subdomains)
    
    if live_domains:
        print_success(f"Live subdomains: {', '.join(live_domains)}")

def unix_check_live_domains(subdomains):
    """Unix-style live domain checking"""
    live_domains = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {}
        
        for domain in subdomains:
            future = executor.submit(check_domain_live, domain)
            future_to_domain[future] = domain
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                is_live = future.result()
                if is_live:
                    live_domains.append(domain)
            except Exception:
                pass
    
    return live_domains

def check_domain_live(domain):
    """Check if a domain responds to HTTP/HTTPS"""
    for protocol in ['https', 'http']:
        try:
            response = session.get(f"{protocol}://{domain}", timeout=5)
            return response.status_code < 400
        except:
            continue
    return False

def whatweb_technologies(target):
    """Enhanced web technology detection with cross-platform support"""
    print_result_header("🧠 Web Technology Detection", f"Target: {target}")
    
    # Validate URL
    is_valid, clean_target, error_msg = validate_target(target, "url")
    if not is_valid:
        print_error(f"Invalid URL: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Analyzing web technologies for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # Check if WhatWeb is available (Unix systems)
        if not sys.platform.startswith('win') and shutil.which('whatweb'):
            whatweb_output = run_command(f"whatweb {target}", timeout=20)
            
            if whatweb_output:
                # Parse WhatWeb output
                technologies = parse_whatweb_output(whatweb_output)
                if technologies:
                    print_result_table(technologies, f"Technologies detected for {target}")
                else:
                    console.print(f"\n[cyan]{whatweb_output}[/cyan]")
            else:
                print_warning("WhatWeb failed, falling back to basic analysis...")
                basic_tech_detection(target)
        else:
            # Use basic technology detection for Windows or when WhatWeb is not available
            print_info("Using built-in technology detection...")
            basic_tech_detection(target)
        
        print_success(f"Technology detection completed for {target}")
        
    except Exception as e:
        print_error(f"Technology detection failed: {str(e)}")

def parse_whatweb_output(output):
    """Parse WhatWeb output into structured data"""
    technologies = []
    
    # WhatWeb output format: URL [Status, Title, Technologies]
    if '[' in output and ']' in output:
        tech_section = output.split('[')[1].split(']')[0]
        tech_items = tech_section.split(',')
        
        for item in tech_items:
            item = item.strip()
            if item and not item.isdigit() and 'Status' not in item:
                # Extract technology name and version if available
                if '[' in item and ']' in item:
                    tech_name = item.split('[')[0].strip()
                    tech_version = item.split('[')[1].split(']')[0]
                    technologies.append({
                        'Technology': tech_name,
                        'Version': tech_version,
                        'Source': 'WhatWeb'
                    })
                else:
                    technologies.append({
                        'Technology': item,
                        'Version': 'Unknown',
                        'Source': 'WhatWeb'
                    })
    
    return technologies

def basic_tech_detection(url):
    """Basic technology detection using HTTP headers (cross-platform)"""
    try:
        if sys.platform.startswith('win'):
            tech_indicators = windows_basic_tech_detection(url)
        else:
            tech_indicators = unix_basic_tech_detection(url)
        
        if tech_indicators:
            print_result_table(tech_indicators, f"Technology Analysis for {url}")
        
    except Exception as e:
        print_error(f"Basic technology detection failed: {str(e)}")

def unix_basic_tech_detection(url):
    """Unix-style basic technology detection"""
    try:
        response = session.get(url, timeout=10)
        headers = response.headers
        
        tech_indicators = {
            'Server': headers.get('Server', 'Unknown'),
            'X-Powered-By': headers.get('X-Powered-By', 'Not disclosed'),
            'X-Generator': headers.get('X-Generator', 'Not disclosed'),
            'X-Framework': headers.get('X-Framework', 'Not disclosed'),
        }
        
        # Add content-based detection
        content = response.text.lower()
        if 'wordpress' in content:
            tech_indicators['CMS'] = 'WordPress'
        elif 'drupal' in content:
            tech_indicators['CMS'] = 'Drupal'
        elif 'joomla' in content:
            tech_indicators['CMS'] = 'Joomla'
        
        # Remove entries with unwanted values
        return {k: v for k, v in tech_indicators.items() 
                if v not in ['Unknown', 'Not disclosed', '']}
        
    except Exception as e:
        print_error(f"Unix technology detection failed: {str(e)}")
        return {}

def ip_geolocation(ip):
    """Enhanced IP geolocation with multiple sources (cross-platform)"""
    print_result_header("🗺️ IP Geolocation", f"IP: {ip}")
    
    # Validate IP
    is_valid, clean_ip, error_msg = validate_target(ip, "ip")
    if not is_valid:
        print_error(f"Invalid IP: {error_msg}")
        return
    
    ip = clean_ip
    print_info(f"Getting geolocation for: [bold cyan]{ip}[/bold cyan]")
    
    # Multiple geolocation services
    services = [
        ('ipinfo.io', f"https://ipinfo.io/{ip}/json"),
        ('ip-api.com', f"http://ip-api.com/json/{ip}"),
    ]
    
    for service_name, url in services:
        try:
            print_info(f"Querying {service_name}...")
            response = session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Normalize data format
                geo_data = normalize_geo_data(data, service_name)
                
                if geo_data:
                    print_result_table(geo_data, f"Geolocation for {ip} (via {service_name})")
                    print_success(f"Geolocation lookup completed using {service_name}")
                    return
                
        except Exception as e:
            print_warning(f"Failed to query {service_name}: {str(e)}")
            continue
    
    print_error("All geolocation services failed")

def normalize_geo_data(data, service):
    """Normalize geolocation data from different services"""
    normalized = {}
    
    if service == 'ipinfo.io':
        normalized = {
            'IP Address': data.get('ip', 'Unknown'),
            'City': data.get('city', 'Unknown'),
            'Region': data.get('region', 'Unknown'),
            'Country': data.get('country', 'Unknown'),
            'Location': data.get('loc', 'Unknown'),
            'Organization': data.get('org', 'Unknown'),
            'Timezone': data.get('timezone', 'Unknown')
        }
    elif service == 'ip-api.com':
        normalized = {
            'IP Address': data.get('query', 'Unknown'),
            'City': data.get('city', 'Unknown'),
            'Region': data.get('regionName', 'Unknown'),
            'Country': data.get('country', 'Unknown'),
            'Location': f"{data.get('lat', 'Unknown')},{data.get('lon', 'Unknown')}",
            'Organization': data.get('isp', 'Unknown'),
            'Timezone': data.get('timezone', 'Unknown')
        }
    
    # Remove entries with 'Unknown' values
    return {k: v for k, v in normalized.items() if v != 'Unknown'}

def extract_metadata(file_path):
    """Enhanced metadata extraction with file validation (cross-platform)"""
    print_result_header("🗂️ Metadata Extraction", f"File: {file_path}")
    
    # Validate file path
    is_valid, clean_path, error_msg = validate_target(file_path, "file")
    if not is_valid:
        print_error(f"Invalid file: {error_msg}")
        return
    
    file_path = clean_path
    print_info(f"Extracting metadata from: [bold cyan]{file_path}[/bold cyan]")
    
    try:
        # Check file size
        file_size = Path(file_path).stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            print_warning(f"Large file detected ({file_size / 1024 / 1024:.1f}MB). This may take a while...")
        
        # Try exiftool if available
        if shutil.which('exiftool'):
            output = run_command(f"exiftool {file_path}", timeout=30)
            
            if output:
                # Parse exiftool output
                metadata = parse_exiftool_output(output)
                
                if metadata:
                    print_result_table(metadata, f"Metadata for {Path(file_path).name}")
                    
                    # Security warnings for sensitive metadata
                    check_sensitive_metadata(metadata)
                    
                    print_success(f"Metadata extraction completed for {file_path}")
                else:
                    console.print(f"\n[cyan]{output}[/cyan]")
            else:
                print_warning("No metadata could be extracted from the file")
        else:
            # Fallback for systems without exiftool
            print_warning("ExifTool not available. Using basic file information...")
            basic_file_info(file_path)
            
    except Exception as e:
        print_error(f"Metadata extraction failed: {str(e)}")

def basic_file_info(file_path):
    """Basic file information when exiftool is not available"""
    try:
        path = Path(file_path)
        stat = path.stat()
        
        info = {
            'File Name': path.name,
            'File Size': f"{stat.st_size:,} bytes",
            'File Type': path.suffix.upper().replace('.', '') or 'Unknown',
            'Modified': time.ctime(stat.st_mtime),
            'Created': time.ctime(stat.st_ctime) if hasattr(stat, 'st_birthtime') else 'Unknown',
        }
        
        print_result_table(info, f"Basic File Information for {path.name}")
        
    except Exception as e:
        print_error(f"Failed to get basic file info: {str(e)}")

def parse_exiftool_output(output):
    """Parse exiftool output into structured data"""
    metadata = {}
    
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            if key and value:
                metadata[key] = value
    
    return metadata

def check_sensitive_metadata(metadata):
    """Check for potentially sensitive metadata"""
    sensitive_fields = [
        'GPS Position', 'GPS Latitude', 'GPS Longitude',
        'Creator', 'Author', 'Owner Name', 'User Comment',
        'Camera Serial Number', 'Lens Serial Number'
    ]
    
    found_sensitive = []
    for field in sensitive_fields:
        if any(field.lower() in key.lower() for key in metadata.keys()):
            found_sensitive.append(field)
    
    if found_sensitive:
        print_warning(f"Potentially sensitive metadata found: {', '.join(found_sensitive)}")
        console.print("[dim]Consider removing metadata before sharing files[/dim]")

def whois_lookup(target):
    """Enhanced WHOIS lookup with validation and better output"""
    print_result_header("🔍 WHOIS Lookup", f"Target: {target}")
    
    # Validate target
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Performing WHOIS lookup for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # Try multiple WHOIS commands for better compatibility
        commands = [
            f"whois {target}",
            f"whois -h whois.iana.org {target}",
        ]
        
        output = None
        for cmd in commands:
            output = run_command(cmd, timeout=15)
            if output and len(output) > 50:  # Valid WHOIS response
                break
        
        if output:
            # Parse and format WHOIS data
            whois_data = parse_whois_output(output)
            if whois_data:
                print_result_table(whois_data, f"WHOIS Information for {target}")
            else:
                # Fallback to raw output
                console.print("\n[cyan]Raw WHOIS Output:[/cyan]")
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('%'):
                        console.print(f"  {line}")
            
            print_success(f"WHOIS lookup completed for {target}")
        else:
            print_warning(f"No WHOIS information found for {target}")
            
    except Exception as e:
        print_error(f"WHOIS lookup failed: {str(e)}")

def parse_whois_output(output):
    """Parse WHOIS output into structured data"""
    data = {}
    important_fields = {
        'Domain Name': ['domain name', 'domain'],
        'Registrar': ['registrar'],
        'Creation Date': ['creation date', 'created', 'registered'],
        'Expiration Date': ['expiration date', 'expires', 'expiry date'],
        'Updated Date': ['updated date', 'last updated', 'modified'],
        'Status': ['status', 'domain status'],
        'Name Servers': ['name server', 'nserver'],
        'Registrant': ['registrant', 'registrant name'],
        'Admin Contact': ['admin', 'administrative contact'],
        'Tech Contact': ['tech', 'technical contact']
    }
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if ':' in line and not line.startswith('%'):
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if value:  # Only add non-empty values
                for display_key, patterns in important_fields.items():
                    if any(pattern in key for pattern in patterns):
                        if display_key in data:
                            if isinstance(data[display_key], list):
                                data[display_key].append(value)
                            else:
                                data[display_key] = [data[display_key], value]
                        else:
                            data[display_key] = value
                        break
    
    return data

def dns_lookup(target):
    """Enhanced DNS lookup with multiple record types and better formatting"""
    print_result_header("🌐 DNS Lookup", f"Target: {target}")
    
    # Validate and clean target
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = sanitize_domain(clean_target)
    print_info(f"Performing DNS lookup for: [bold cyan]{target}[/bold cyan]")
    
    # DNS record types to query
    record_types = {
        'A': 'IPv4 Address',
        'AAAA': 'IPv6 Address', 
        'MX': 'Mail Exchange',
        'NS': 'Name Servers',
        'TXT': 'Text Records',
        'CNAME': 'Canonical Name',
        'SOA': 'Start of Authority'
    }
    
    dns_results = {}
    
    with create_progress_bar("DNS Lookup") as progress:
        task = progress.add_task("Querying DNS records...", total=len(record_types))
        
        for record_type, description in record_types.items():
            try:
                # Use dnspython for more reliable DNS queries
                answers = dns.resolver.resolve(target, record_type)
                results = []
                
                for answer in answers:
                    if record_type == 'MX':
                        results.append(f"{answer.preference} {answer.exchange}")
                    elif record_type == 'SOA':
                        results.append(f"Primary: {answer.mname}, Email: {answer.rname}")
                    else:
                        results.append(str(answer))
                
                if results:
                    dns_results[f"{record_type} ({description})"] = results
                    
            except dns.resolver.NXDOMAIN:
                dns_results[f"{record_type} ({description})"] = ["Domain does not exist"]
            except dns.resolver.NoAnswer:
                dns_results[f"{record_type} ({description})"] = ["No records found"]
            except Exception as e:
                dns_results[f"{record_type} ({description})"] = [f"Query failed: {str(e)}"]
            
            progress.advance(task)
    
    if dns_results:
        print_result_table(dns_results, f"DNS Records for {target}")
        print_success(f"DNS lookup completed for {target}")
    else:
        print_warning(f"No DNS records found for {target}")

def reverse_ip_lookup(target):
    """Enhanced reverse IP lookup with geolocation"""
    print_result_header("🔄 Reverse IP Lookup", f"Target: {target}")
    
    # Validate IP or domain
    is_valid, clean_target, error_msg = validate_target(target, "domain")
    if not is_valid:
        print_error(f"Invalid target: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Performing reverse lookup for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # If target is a domain, resolve to IP first
        if not target.replace('.', '').isdigit():
            try:
                ip = socket.gethostbyname(target)
                print_info(f"Resolved {target} to IP: {ip}")
                target = ip
            except socket.gaierror:
                print_error(f"Could not resolve domain: {target}")
                return
        
        # Perform reverse lookup
        try:
            hostname = socket.gethostbyaddr(target)[0]
            result = {
                'IP Address': target,
                'Hostname': hostname,
                'Status': 'Reverse lookup successful'
            }
        except socket.herror:
            result = {
                'IP Address': target,
                'Hostname': 'No reverse DNS record',
                'Status': 'No PTR record found'
            }
        
        # Try to get additional info using dig command
        ptr_output = run_command(f"dig -x {target} +short", show_progress=False)
        if ptr_output and ptr_output != result.get('Hostname', ''):
            result['PTR Record'] = ptr_output
        
        print_result_table(result, f"Reverse Lookup for {target}")
        print_success(f"Reverse lookup completed for {target}")
        
    except Exception as e:
        print_error(f"Reverse lookup failed: {str(e)}")

async def fetch_url(session, url, timeout=10):
    """Async URL fetcher"""
    try:
        async with session.get(url, timeout=timeout) as response:
            return await response.text()
    except Exception as e:
        return f"Error: {str(e)}"

def subdomains_crtsh(domain):
    """Enhanced subdomain enumeration using crt.sh with async requests"""
    print_result_header("🔍 Subdomain Enumeration", f"Domain: {domain}")
    
    # Validate domain
    is_valid, clean_domain, error_msg = validate_target(domain, "domain")
    if not is_valid:
        print_error(f"Invalid domain: {error_msg}")
        return
    
    domain = sanitize_domain(clean_domain)
    print_info(f"Searching subdomains for: [bold cyan]{domain}[/bold cyan]")
    
    try:
        # Use requests instead of curl for better error handling
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        with create_progress_bar("Subdomain Search") as progress:
            task = progress.add_task("Querying crt.sh...", total=None)
            
            response = session.get(url, timeout=30)
            progress.update(task, completed=True)
        
        if response.status_code == 200:
            try:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple domains in one entry
                        domains = name_value.split('\n')
                        for sub in domains:
                            sub = sub.strip()
                            if sub and domain in sub:
                                # Clean wildcard entries
                                if sub.startswith('*.'):
                                    sub = sub[2:]
                                subdomains.add(sub.lower())
                
                if subdomains:
                    # Sort subdomains
                    sorted_subs = sorted(list(subdomains))
                    
                    # Create table data
                    table_data = []
                    for i, subdomain in enumerate(sorted_subs, 1):
                        table_data.append({
                            '#': i,
                            'Subdomain': subdomain,
                            'Type': 'Certificate Log'
                        })
                    
                    print_result_table(table_data, f"Subdomains found for {domain} ({len(sorted_subs)} total)")
                    print_success(f"Found {len(sorted_subs)} unique subdomains")
                    
                    # Optional: Check which subdomains are live
                    if len(sorted_subs) <= 20:  # Only for small lists
                        check_live_subdomains(sorted_subs[:10])  # Check first 10
                else:
                    print_warning(f"No subdomains found for {domain}")
                    
            except json.JSONDecodeError:
                print_error("Failed to parse JSON response from crt.sh")
        else:
            print_error(f"crt.sh query failed with status: {response.status_code}")
            
    except Exception as e:
        print_error(f"Subdomain enumeration failed: {str(e)}")

def check_live_subdomains(subdomains):
    """Check if subdomains are live (optional feature)"""
    print_info("Checking live status for top subdomains...")
    
    live_domains = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {}
        
        for domain in subdomains:
            future = executor.submit(check_domain_live, domain)
            future_to_domain[future] = domain
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                is_live = future.result()
                if is_live:
                    live_domains.append(domain)
            except Exception:
                pass
    
    if live_domains:
        print_success(f"Live subdomains: {', '.join(live_domains)}")

def check_domain_live(domain):
    """Check if a domain responds to HTTP/HTTPS"""
    for protocol in ['https', 'http']:
        try:
            response = session.get(f"{protocol}://{domain}", timeout=5)
            return response.status_code < 400
        except:
            continue
    return False

def whatweb_technologies(target):
    """Enhanced web technology detection"""
    print_result_header("🧠 Web Technology Detection", f"Target: {target}")
    
    # Validate URL
    is_valid, clean_target, error_msg = validate_target(target, "url")
    if not is_valid:
        print_error(f"Invalid URL: {error_msg}")
        return
    
    target = clean_target
    print_info(f"Analyzing web technologies for: [bold cyan]{target}[/bold cyan]")
    
    try:
        # Try WhatWeb first (if available)
        whatweb_output = run_command(f"whatweb {target}", timeout=20)
        
        if whatweb_output:
            # Parse WhatWeb output
            technologies = parse_whatweb_output(whatweb_output)
            if technologies:
                print_result_table(technologies, f"Technologies detected for {target}")
            else:
                console.print(f"\n[cyan]{whatweb_output}[/cyan]")
        else:
            # Fallback: Basic header analysis
            print_warning("WhatWeb not available, performing basic analysis...")
            basic_tech_detection(target)
        
        print_success(f"Technology detection completed for {target}")
        
    except Exception as e:
        print_error(f"Technology detection failed: {str(e)}")

def parse_whatweb_output(output):
    """Parse WhatWeb output into structured data"""
    technologies = []
    
    # WhatWeb output format: URL [Status, Title, Technologies]
    if '[' in output and ']' in output:
        tech_section = output.split('[')[1].split(']')[0]
        tech_items = tech_section.split(',')
        
        for item in tech_items:
            item = item.strip()
            if item and not item.isdigit() and 'Status' not in item:
                # Extract technology name and version if available
                if '[' in item and ']' in item:
                    tech_name = item.split('[')[0].strip()
                    tech_version = item.split('[')[1].split(']')[0]
                    technologies.append({
                        'Technology': tech_name,
                        'Version': tech_version,
                        'Source': 'WhatWeb'
                    })
                else:
                    technologies.append({
                        'Technology': item,
                        'Version': 'Unknown',
                        'Source': 'WhatWeb'
                    })
    
    return technologies

def basic_tech_detection(url):
    """Basic technology detection using HTTP headers"""
    try:
        response = session.get(url, timeout=10)
        headers = response.headers
        
        tech_indicators = {
            'Server': headers.get('Server', 'Unknown'),
            'X-Powered-By': headers.get('X-Powered-By', 'Not disclosed'),
            'X-Generator': headers.get('X-Generator', 'Not disclosed'),
            'X-Framework': headers.get('X-Framework', 'Not disclosed'),
        }
        
        # Add content-based detection
        content = response.text.lower()
        if 'wordpress' in content:
            tech_indicators['CMS'] = 'WordPress'
        elif 'drupal' in content:
            tech_indicators['CMS'] = 'Drupal'
        elif 'joomla' in content:
            tech_indicators['CMS'] = 'Joomla'
        
        print_result_table(tech_indicators, f"Basic Technology Analysis for {url}")
        
    except Exception as e:
        print_error(f"Basic technology detection failed: {str(e)}")

def ip_geolocation(ip):
    """Enhanced IP geolocation with multiple sources"""
    print_result_header("🗺️ IP Geolocation", f"IP: {ip}")
    
    # Validate IP
    is_valid, clean_ip, error_msg = validate_target(ip, "ip")
    if not is_valid:
        print_error(f"Invalid IP: {error_msg}")
        return
    
    ip = clean_ip
    print_info(f"Getting geolocation for: [bold cyan]{ip}[/bold cyan]")
    
    # Multiple geolocation services
    services = [
        ('ipinfo.io', f"https://ipinfo.io/{ip}/json"),
        ('ip-api.com', f"http://ip-api.com/json/{ip}"),
    ]
    
    for service_name, url in services:
        try:
            print_info(f"Querying {service_name}...")
            response = session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Normalize data format
                geo_data = normalize_geo_data(data, service_name)
                
                if geo_data:
                    print_result_table(geo_data, f"Geolocation for {ip} (via {service_name})")
                    print_success(f"Geolocation lookup completed using {service_name}")
                    return
                
        except Exception as e:
            print_warning(f"Failed to query {service_name}: {str(e)}")
            continue
    
    print_error("All geolocation services failed")

def normalize_geo_data(data, service):
    """Normalize geolocation data from different services"""
    normalized = {}
    
    if service == 'ipinfo.io':
        normalized = {
            'IP Address': data.get('ip', 'Unknown'),
            'City': data.get('city', 'Unknown'),
            'Region': data.get('region', 'Unknown'),
            'Country': data.get('country', 'Unknown'),
            'Location': data.get('loc', 'Unknown'),
            'Organization': data.get('org', 'Unknown'),
            'Timezone': data.get('timezone', 'Unknown')
        }
    elif service == 'ip-api.com':
        normalized = {
            'IP Address': data.get('query', 'Unknown'),
            'City': data.get('city', 'Unknown'),
            'Region': data.get('regionName', 'Unknown'),
            'Country': data.get('country', 'Unknown'),
            'Location': f"{data.get('lat', 'Unknown')},{data.get('lon', 'Unknown')}",
            'Organization': data.get('isp', 'Unknown'),
            'Timezone': data.get('timezone', 'Unknown')
        }
    
    # Remove entries with 'Unknown' values
    return {k: v for k, v in normalized.items() if v != 'Unknown'}

def extract_metadata(file_path):
    """Enhanced metadata extraction with file validation"""
    print_result_header("🗂️ Metadata Extraction", f"File: {file_path}")
    
    # Validate file path
    is_valid, clean_path, error_msg = validate_target(file_path, "file")
    if not is_valid:
        print_error(f"Invalid file: {error_msg}")
        return
    
    file_path = clean_path
    print_info(f"Extracting metadata from: [bold cyan]{file_path}[/bold cyan]")
    
    try:
        # Check file size
        file_size = Path(file_path).stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            print_warning(f"Large file detected ({file_size / 1024 / 1024:.1f}MB). This may take a while...")
        
        # Extract metadata using exiftool
        output = run_command(f"exiftool {file_path}", timeout=30)
        
        if output:
            # Parse exiftool output
            metadata = parse_exiftool_output(output)
            
            if metadata:
                print_result_table(metadata, f"Metadata for {Path(file_path).name}")
                
                # Security warnings for sensitive metadata
                check_sensitive_metadata(metadata)
                
                print_success(f"Metadata extraction completed for {file_path}")
            else:
                console.print(f"\n[cyan]{output}[/cyan]")
        else:
            print_warning("No metadata could be extracted from the file")
            
    except Exception as e:
        print_error(f"Metadata extraction failed: {str(e)}")

def parse_exiftool_output(output):
    """Parse exiftool output into structured data"""
    metadata = {}
    
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            if key and value:
                metadata[key] = value
    
    return metadata

def check_sensitive_metadata(metadata):
    """Check for potentially sensitive metadata"""
    sensitive_fields = [
        'GPS Position', 'GPS Latitude', 'GPS Longitude',
        'Creator', 'Author', 'Owner Name', 'User Comment',
        'Camera Serial Number', 'Lens Serial Number'
    ]
    
    found_sensitive = []
    for field in sensitive_fields:
        if any(field.lower() in key.lower() for key in metadata.keys()):
            found_sensitive.append(field)
    
    if found_sensitive:
        print_warning(f"Potentially sensitive metadata found: {', '.join(found_sensitive)}")
        console.print("[dim]Consider removing metadata before sharing files[/dim]")
