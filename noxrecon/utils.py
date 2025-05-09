import subprocess

def run_command(command):
    """Ejecuta un comando en la shell y devuelve la salida."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[!] Error ejecutando comando: {e}"

def print_banner():
    banner = r"""

███╗░░██╗░█████╗░██╗░░██╗██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
████╗░██║██╔══██╗╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
██╔██╗██║██║░░██║░╚███╔╝░██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
██║╚████║██║░░██║░██╔██╗░██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
██║░╚███║╚█████╔╝██╔╝╚██╗██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝
                                                     
    OSINT Reconnaissance Toolkit — by Pentesters, for Pentesters
    """
    print(banner)
