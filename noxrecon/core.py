from .utils import run_command, print_info, print_success, print_warning, print_error, CYAN, MAGENTA, RED, GREEN, YELLOW, RESET

def whois_lookup(target):
    print_info(f"{RED}Realizando WHOIS para: {target}")
    output = run_command(f"whois {target}")
    if output:
        print_success(f"{CYAN}\n{'='*40} WHOIS RESULTADOS {'='*40}\n{output}\n{'='*100}")

def dns_lookup(target):
    print_info(f"{RED}Realizando consulta DNS para {target}...")
    records = ["A", "MX", "NS"]
    for record in records:
        output = run_command(f"dig {target} {record} +short")
        if output:
            print_success(f"{MAGENTA}\n{'='*10} {record} Records {'='*10}\n{CYAN}{output}\n{'='*40}")
        else:
            print_warning(f"No se encontraron registros {record} para {target}")

def reverse_ip_lookup(target):
    print_info(f"{RED}Realizando Reverse IP Lookup para: {target}")
    output = run_command(f"host {target}")
    if output:
        print_success(f"{CYAN}\n{'='*40} Reverse IP Resultados {'='*40}\n{output}\n{'='*100}")

def subdomains_crtsh(domain):
    print_info(f"{RED}Buscando subdominios en crt.sh para: {domain}")
    command = f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r ".[].name_value" | sort -u'
    output = run_command(command)
    if output:
        print_success(f"{CYAN}\n{'='*40} Subdominios encontrados {'='*40}\n{output}\n{'='*100}")

def whatweb_technologies(target):
    print_info(f"{RED}Detectando tecnologías con WhatWeb en: {target}")
    output = run_command(f"whatweb {target}")
    if output:
        print_success(f"{CYAN}\n{'='*40} WhatWeb Resultados {'='*40}\n{output}\n{'='*100}")

def ip_geolocation(ip):
    print_info(f"{RED}Obteniendo geolocalización para IP: {ip}")
    output = run_command(f"curl -s https://ipinfo.io/{ip}/json")
    if output:
        print_success(f"{CYAN}\n{'='*40} Geolocalización {'='*40}\n{output}\n{'='*100}")

def extract_metadata(file_path):
    print_info(f"{RED}Extrayendo metadatos del archivo: {file_path}")
    output = run_command(f"exiftool {file_path}")
    if output:
        print_success(f"{CYAN}\n{'='*40} Metadatos {'='*40}\n{output}\n{'='*100}")
