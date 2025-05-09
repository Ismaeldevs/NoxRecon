from .utils import run_command

def whois_lookup(domain):
    """Realiza un whois del dominio."""
    print(f"[+] WHOIS lookup para: {domain}")
    command = f"whois {domain}"
    return run_command(command)

def dns_lookup(domain):
    """Realiza un lookup de registros DNS A y MX."""
    print(f"[+] DNS lookup para: {domain}")
    command = f"dig {domain} A +short; dig {domain} MX +short"
    return run_command(command)

def reverse_ip_lookup(ip):
    """Realiza un reverse IP lookup usando host."""
    print(f"[+] Reverse IP lookup para: {ip}")
    command = f"host {ip}"
    return run_command(command)
