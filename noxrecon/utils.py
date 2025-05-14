import subprocess
from colorama import Fore, Style

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

def print_banner():
    banner = f"""{RED}
███╗░░██╗░█████╗░██╗░░██╗██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
████╗░██║██╔══██╗╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
██╔██╗██║██║░░██║░╚███╔╝░██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
██║╚████║██║░░██║░██╔██╗░██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
██║░╚███║╚█████╔╝██╔╝╚██╗██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝

{MAGENTA}OSINT Reconnaissance Toolkit — by Pentesters, for Pentesters
                                                                             
{YELLOW}[*] Author: NoxRecon Team
[*] NoxRecon v2.0.0 - Red Team OSINT Toolkit
[*] Github: https://github.com/Ismaeldevs
{RESET}"""
    print(banner)

def print_info(msg): print(f"{CYAN}[i] {msg}{RESET}")
def print_success(msg): print(f"{GREEN}[✓] {msg}{RESET}")
def print_warning(msg): print(f"{YELLOW}[!] {msg}{RESET}")
def print_error(msg): print(f"{RED}[x] {msg}{RESET}")

def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, text=True)
        return output.strip()
    except subprocess.CalledProcessError:
        print_error(f"Error ejecutando comando: {command}")
        return None
