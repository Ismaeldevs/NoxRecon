"""
Enhanced menu system for NoxRecon with questionary integration
Provides a modern, interactive CLI experience
"""
import sys
import os
from pathlib import Path
import questionary
from questionary import Style

from .utils import (
    print_banner, print_info, print_success, print_warning, print_error,
    check_dependencies, clear_screen, wait_for_enter, print_separator,
    console, CYAN, RED, GREEN, YELLOW, RESET
)
from .validators import prompt_with_validation
from . import core

# Custom style for questionary
custom_style = Style([
    ('qmark', 'fg:#ff0066 bold'),           # Question mark
    ('question', 'bold'),                    # Question text
    ('answer', 'fg:#44ff00 bold'),          # Answer text
    ('pointer', 'fg:#ff0066 bold'),         # Pointer used in select and checkbox prompts
    ('highlighted', 'fg:#ff0066 bold'),     # Highlighted text in select and checkbox prompts
    ('selected', 'fg:#cc5454'),             # Selected text color in checkbox prompts
    ('separator', 'fg:#cc5454'),            # Separator in checkbox prompts
    ('instruction', ''),                     # Instruction for the user
    ('text', ''),                           # Plain text
    ('disabled', 'fg:#858585 italic')       # Disabled choices
])

def show_startup_checks():
    """Perform startup checks and show system status"""
    print_info("Performing system checks...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print_error("Python 3.8 or higher is required")
        return False
    else:
        print_success(f"Python version: {sys.version.split()[0]}")
    
    # Check dependencies
    if not check_dependencies():
        print_error("Please install missing dependencies before using NoxRecon")
        return False
    
    print_success("All system checks passed!")
    print_separator()
    return True

def show_main_menu():
    """Display the main menu with questionary"""
    
    menu_choices = [
        {
            'name': '🔍 WHOIS Lookup - Domain/IP registration information',
            'value': 'whois'
        },
        {
            'name': '🌐 DNS Lookup - Domain Name System records',
            'value': 'dns'
        },
        {
            'name': '🔄 Reverse IP Lookup - IP to hostname resolution',
            'value': 'reverse_ip'
        },
        {
            'name': '🎯 Subdomain Enumeration - Find subdomains via crt.sh',
            'value': 'subdomains'
        },
        {
            'name': '🧠 Web Technology Detection - Analyze web technologies',
            'value': 'whatweb'
        },
        {
            'name': '🗺️ IP Geolocation - Geographic location of IP addresses',
            'value': 'geolocation'
        },
        {
            'name': '🗂️ Metadata Extraction - Extract file metadata',
            'value': 'metadata'
        },
        questionary.Separator(),
        {
            'name': '⚙️ Settings & Configuration',
            'value': 'settings'
        },
        {
            'name': '📖 Help & Documentation',
            'value': 'help'
        },
        questionary.Separator(),
        {
            'name': '🚪 Exit NoxRecon',
            'value': 'exit'
        }
    ]
    
    try:
        choice = questionary.select(
            "Select an OSINT operation:",
            choices=menu_choices,
            style=custom_style
        ).ask()
        
        return choice
    except KeyboardInterrupt:
        print_warning("\nOperation cancelled by user")
        return 'exit'
    except EOFError:
        return 'exit'

def handle_whois_lookup():
    """Handle WHOIS lookup with enhanced input validation"""
    console.print("\n[bold cyan]🔍 WHOIS Lookup[/bold cyan]")
    console.print("[dim]Get registration information for domains and IP addresses[/dim]\n")
    
    target = prompt_with_validation(
        "[-] Enter domain or IP address: ",
        target_type="domain"
    )
    
    if target:
        try:
            core.whois_lookup(target)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"WHOIS lookup failed: {str(e)}")

def handle_dns_lookup():
    """Handle DNS lookup with validation"""
    console.print("\n[bold cyan]🌐 DNS Lookup[/bold cyan]")
    console.print("[dim]Query DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)[/dim]\n")
    
    target = prompt_with_validation(
        "[-] Enter domain name: ",
        target_type="domain"
    )
    
    if target:
        try:
            core.dns_lookup(target)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"DNS lookup failed: {str(e)}")

def handle_reverse_ip():
    """Handle reverse IP lookup"""
    console.print("\n[bold cyan]🔄 Reverse IP Lookup[/bold cyan]")
    console.print("[dim]Resolve IP addresses to hostnames[/dim]\n")
    
    target = prompt_with_validation(
        "[-] Enter IP address or domain: ",
        target_type="domain"
    )
    
    if target:
        try:
            core.reverse_ip_lookup(target)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"Reverse lookup failed: {str(e)}")

def handle_subdomains():
    """Handle subdomain enumeration"""
    console.print("\n[bold cyan]🎯 Subdomain Enumeration[/bold cyan]")
    console.print("[dim]Find subdomains using Certificate Transparency logs[/dim]\n")
    
    domain = prompt_with_validation(
        "[-] Enter domain name: ",
        target_type="domain"
    )
    
    if domain:
        try:
            core.subdomains_crtsh(domain)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"Subdomain enumeration failed: {str(e)}")

def handle_whatweb():
    """Handle web technology detection"""
    console.print("\n[bold cyan]🧠 Web Technology Detection[/bold cyan]")
    console.print("[dim]Analyze web technologies, frameworks, and servers[/dim]\n")
    
    target = prompt_with_validation(
        "[-] Enter URL (e.g., https://example.com): ",
        target_type="url"
    )
    
    if target:
        try:
            core.whatweb_technologies(target)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"Technology detection failed: {str(e)}")

def handle_geolocation():
    """Handle IP geolocation"""
    console.print("\n[bold cyan]🗺️ IP Geolocation[/bold cyan]")
    console.print("[dim]Get geographic information for IP addresses[/dim]\n")
    
    ip = prompt_with_validation(
        "[-] Enter IP address: ",
        target_type="ip"
    )
    
    if ip:
        try:
            core.ip_geolocation(ip)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"Geolocation lookup failed: {str(e)}")

def handle_metadata():
    """Handle metadata extraction"""
    console.print("\n[bold cyan]🗂️ Metadata Extraction[/bold cyan]")
    console.print("[dim]Extract metadata from files (images, documents, etc.)[/dim]\n")
    
    file_path = prompt_with_validation(
        "[-] Enter file path: ",
        target_type="file"
    )
    
    if file_path:
        try:
            core.extract_metadata(file_path)
        except KeyboardInterrupt:
            print_warning("Operation cancelled")
        except Exception as e:
            print_error(f"Metadata extraction failed: {str(e)}")

def show_settings_menu():
    """Show settings and configuration options"""
    console.print("\n[bold cyan]⚙️ Settings & Configuration[/bold cyan]\n")
    
    settings_choices = [
        {
            'name': '🔧 Check System Dependencies',
            'value': 'deps'
        },
        {
            'name': '📊 Show System Information',
            'value': 'sysinfo'
        },
        {
            'name': '🔄 Update Check (Placeholder)',
            'value': 'update'
        },
        questionary.Separator(),
        {
            'name': '← Back to Main Menu',
            'value': 'back'
        }
    ]
    
    try:
        choice = questionary.select(
            "Select a setting:",
            choices=settings_choices,
            style=custom_style
        ).ask()
        
        if choice == 'deps':
            check_dependencies()
        elif choice == 'sysinfo':
            show_system_info()
        elif choice == 'update':
            print_info("Update checking feature is not implemented yet")
        
        return choice != 'back'
        
    except (KeyboardInterrupt, EOFError):
        return False

def show_system_info():
    """Display system information"""
    import platform
    
    info = {
        'Operating System': platform.system(),
        'OS Version': platform.release(),
        'Architecture': platform.machine(),
        'Python Version': platform.python_version(),
        'Python Executable': sys.executable,
        'Working Directory': os.getcwd()
    }
    
    from .utils import print_result_table
    print_result_table(info, "System Information")

def show_help_menu():
    """Show help and documentation"""
    console.print("\n[bold cyan]📖 Help & Documentation[/bold cyan]\n")
    
    help_text = """
[bold yellow]NoxRecon - Advanced OSINT Toolkit[/bold yellow]

[bold cyan]Available Operations:[/bold cyan]

🔍 [bold]WHOIS Lookup[/bold]
   Get domain registration information, registrar details, and expiration dates
   
🌐 [bold]DNS Lookup[/bold]  
   Query various DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
   
🔄 [bold]Reverse IP Lookup[/bold]
   Resolve IP addresses back to hostnames using PTR records
   
🎯 [bold]Subdomain Enumeration[/bold]
   Find subdomains using Certificate Transparency logs via crt.sh
   
🧠 [bold]Web Technology Detection[/bold]
   Identify web servers, frameworks, CMS, and other technologies
   
🗺️ [bold]IP Geolocation[/bold]
   Get geographic location, ISP, and organization information for IPs
   
🗂️ [bold]Metadata Extraction[/bold]
   Extract EXIF and other metadata from files

[bold yellow]Tips for Professional Use:[/bold yellow]

• Always ensure you have proper authorization before scanning targets
• Use rate limiting and be respectful of target resources  
• Cross-reference results from multiple sources for accuracy
• Keep logs of your reconnaissance activities for reporting
• Be aware of legal restrictions in your jurisdiction

[bold red]Important Legal Notice:[/bold red]
This tool is for authorized security testing and educational purposes only.
Unauthorized scanning or reconnaissance may violate laws and terms of service.
"""
    
    console.print(help_text)

def main_menu():
    """Main application loop"""
    try:
        # Clear screen and show banner
        clear_screen()
        print_banner()
        
        # Perform startup checks
        if not show_startup_checks():
            print_error("Startup checks failed. Exiting...")
            sys.exit(1)
        
        console.print("[bold green]Welcome to NoxRecon![/bold green]")
        console.print("[dim]Professional OSINT toolkit for security professionals[/dim]\n")
        
        # Main application loop
        while True:
            try:
                choice = show_main_menu()
                
                if choice == 'exit' or choice is None:
                    break
                elif choice == 'whois':
                    handle_whois_lookup()
                elif choice == 'dns':
                    handle_dns_lookup()
                elif choice == 'reverse_ip':
                    handle_reverse_ip()
                elif choice == 'subdomains':
                    handle_subdomains()
                elif choice == 'whatweb':
                    handle_whatweb()
                elif choice == 'geolocation':
                    handle_geolocation()
                elif choice == 'metadata':
                    handle_metadata()
                elif choice == 'settings':
                    while show_settings_menu():
                        pass
                elif choice == 'help':
                    show_help_menu()
                
                # Wait for user after each operation
                if choice != 'settings' and choice != 'help':
                    wait_for_enter()
                
            except KeyboardInterrupt:
                print_warning("\n\nOperation interrupted by user")
                if questionary.confirm("Do you want to exit NoxRecon?", style=custom_style).ask():
                    break
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                console.print("[dim]Please report this error if it persists[/dim]")
                wait_for_enter()
        
        # Exit message
        console.print("\n[bold green]Thank you for using NoxRecon![/bold green]")
        console.print("[dim]Stay safe and always get proper authorization[/dim]")
        
    except KeyboardInterrupt:
        print_warning("\nNoxRecon terminated by user")
    except Exception as e:
        print_error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main_menu()
