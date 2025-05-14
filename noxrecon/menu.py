import sys
from .utils import print_banner, print_info, print_success, print_warning, print_error, CYAN, RED, GREEN, YELLOW, RESET
from . import core

def main_menu():
    print_banner()
    while True:
        print(f"""
{RED}[1]{RESET} WHOIS Lookup
{RED}[2]{RESET} DNS Lookup
{RED}[3]{RESET} Reverse IP Lookup
{RED}[4]{RESET} Subdominios (crt.sh)
{RED}[5]{RESET} Detección de tecnologías (WhatWeb)
{RED}[6]{RESET} Geolocalización de IP
{RED}[7]{RESET} Extracción de metadatos (Exiftool)
{RED}[0]{RESET} Salir
""")
        option = input(f"{YELLOW}[?] Selecciona una opción: {RESET}")

        if option == "1":
            target = input(f"{CYAN}[-] Dominio/IP: {RESET}")
            core.whois_lookup(target)

        elif option == "2":
            target = input(f"{CYAN}[-] Dominio: {RESET}")
            core.dns_lookup(target)

        elif option == "3":
            target = input(f"{CYAN}[-] Dominio: {RESET}")
            core.reverse_ip_lookup(target)

        elif option == "4":
            domain = input(f"{CYAN}[-] Dominio: {RESET}")
            core.subdomains_crtsh(domain)

        elif option == "5":
            target = input(f"{CYAN}[-] URL: {RESET}")
            core.whatweb_technologies(target)

        elif option == "6":
            ip = input(f"{CYAN}[-] IP: {RESET}")
            core.ip_geolocation(ip)

        elif option == "7":
            file_path = input(f"{CYAN}[-] Ruta del archivo: {RESET}")
            core.extract_metadata(file_path)

        elif option == "0":
            print_success("Saliendo de NoxRecon. ¡Hasta luego!")
            sys.exit()

        else:
            print_warning("Opción inválida. Intenta de nuevo.")
