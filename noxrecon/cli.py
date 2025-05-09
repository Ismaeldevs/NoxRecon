import argparse
from .core import whois_lookup, dns_lookup, reverse_ip_lookup
from .utils import print_banner

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog='noxrecon',
        description='NoxRecon - OSINT Reconnaissance Toolkit',
        epilog='Happy Hunting! ⚔️'
    )
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # WHOIS
    parser_whois = subparsers.add_parser('whois', help='Realiza WHOIS lookup')
    parser_whois.add_argument('domain', help='Dominio objetivo')

    # DNS
    parser_dns = subparsers.add_parser('dns', help='Realiza DNS lookup')
    parser_dns.add_argument('domain', help='Dominio objetivo')

    # Reverse IP
    parser_reverse = subparsers.add_parser('reverse', help='Realiza Reverse IP lookup')
    parser_reverse.add_argument('ip', help='IP objetivo')

    args = parser.parse_args()

    if args.command == 'whois':
        output = whois_lookup(args.domain)
        print(output)
    elif args.command == 'dns':
        output = dns_lookup(args.domain)
        print(output)
    elif args.command == 'reverse':
        output = reverse_ip_lookup(args.ip)
        print(output)
    else:
        parser.print_help()
