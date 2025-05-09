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
 _   _                _____                           
| \ | | _____      __| ____|_ __   ___ ___  ___ _ __ 
|  \| |/ _ \ \ /\ / /|  _| | '_ \ / __/ _ \/ _ \ '__|
| |\  |  __/\ V  V / | |___| | | | (_|  __/  __/ |   
|_| \_|\___| \_/\_/  |_____|_| |_|\___\___|\___|_|   
                                                     
    OSINT Reconnaissance Toolkit — by Pentesters, for Pentesters
    """
    print(banner)
