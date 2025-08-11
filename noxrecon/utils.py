import subprocess
import sys
import time
import shutil
from pathlib import Path
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Color constants
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
WHITE = Fore.WHITE
RESET = Style.RESET_ALL
BRIGHT = Style.BRIGHT
DIM = Style.DIM

# Rich console instance
console = Console()

def print_banner():
    """Display the enhanced NoxRecon banner"""
    banner_text = """
███╗░░██╗░█████╗░██╗░░██╗██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
████╗░██║██╔══██╗╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
██╔██╗██║██║░░██║░╚███╔╝░██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
██║╚████║██║░░██║░██╔██╗░██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
██║░╚███║╚█████╔╝██╔╝╚██╗██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝
"""
    
    # Create the banner panel with rich styling
    banner_panel = Panel(
        Text(banner_text, style="bold red") +
        Text("\n🕵️‍♂️ Advanced OSINT Reconnaissance Toolkit\n", style="bold magenta") +
        Text("by Pentesters, for Pentesters\n", style="bold cyan") +
        Text("Version 2.0.0 | Enhanced Edition", style="bold yellow"),
        box=box.DOUBLE,
        border_style="red",
        title="[bold white]NoxRecon[/bold white]",
        subtitle="[dim]Professional Grade OSINT[/dim]"
    )
    
    console.print(banner_panel)
    
    # Author and info
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="bold yellow")
    info_table.add_column(style="cyan")
    
    info_table.add_row("👨‍💻 Author:", "NoxRecon Team (@Ismaeldevs)")
    info_table.add_row("🌐 GitHub:", "https://github.com/Ismaeldevs/NoxRecon")
    info_table.add_row("📜 License:", "MIT License")
    info_table.add_row("⚠️  Usage:", "Authorized penetration testing only")
    
    console.print(info_table)
    console.print()

def print_info(msg): 
    """Print info message with icon"""
    console.print(f"[bold cyan]ℹ️  [/bold cyan]{msg}")

def print_success(msg): 
    """Print success message with icon"""
    console.print(f"[bold green]✅ [/bold green]{msg}")

def print_warning(msg): 
    """Print warning message with icon"""
    console.print(f"[bold yellow]⚠️  [/bold yellow]{msg}")

def print_error(msg): 
    """Print error message with icon"""
    console.print(f"[bold red]❌ [/bold red]{msg}")

def print_result_header(title, subtitle=""):
    """Print a styled header for results"""
    if subtitle:
        title_text = f"{title}\n{subtitle}"
    else:
        title_text = title
    
    header = Panel(
        title_text,
        box=box.ROUNDED,
        border_style="green",
        title_align="center"
    )
    console.print(header)

def print_result_table(data, title="Results"):
    """Print results in a formatted table"""
    if not data:
        print_warning("No results found")
        return
    
    table = Table(title=title, box=box.ROUNDED, border_style="cyan")
    
    # If data is a list of dicts, use keys as columns
    if isinstance(data, list) and data and isinstance(data[0], dict):
        columns = list(data[0].keys())
        for col in columns:
            table.add_column(col, style="cyan")
        
        for item in data:
            table.add_row(*[str(item.get(col, "")) for col in columns])
    
    # If data is a dict, show key-value pairs
    elif isinstance(data, dict):
        table.add_column("Property", style="yellow")
        table.add_column("Value", style="cyan")
        
        for key, value in data.items():
            table.add_row(str(key), str(value))
    
    # If data is a list of strings
    elif isinstance(data, list):
        table.add_column("Results", style="cyan")
        for item in data:
            table.add_row(str(item))
    
    # If data is a string
    else:
        table.add_column("Output", style="cyan")
        for line in str(data).split('\n'):
            if line.strip():
                table.add_row(line.strip())
    
    console.print(table)

def run_command(command, timeout=30, show_progress=True):
    """
    Execute shell command with timeout and optional progress indicator
    """
    try:
        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(f"Executing: {command[:50]}...", total=None)
                
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    universal_newlines=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    progress.update(task, completed=True)
                    
                    if process.returncode == 0:
                        return stdout.strip() if stdout else ""
                    else:
                        if stderr:
                            print_error(f"Command failed: {stderr.strip()}")
                        return None
                        
                except subprocess.TimeoutExpired:
                    process.kill()
                    print_error(f"Command timed out after {timeout} seconds")
                    return None
        else:
            # Execute without progress indicator
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                return result.stdout.strip() if result.stdout else ""
            else:
                if result.stderr:
                    print_error(f"Command failed: {result.stderr.strip()}")
                return None
                
    except subprocess.TimeoutExpired:
        print_error(f"Command timed out after {timeout} seconds")
        return None
    except Exception as e:
        print_error(f"Error executing command: {str(e)}")
        return None

def check_dependencies():
    """Check if required external tools are installed (Windows-aware)"""
    import sys
    
    required_tools = {
        'python': 'Python interpreter (already available)',
    }
    
    optional_tools = {
        'whois': 'WHOIS lookup functionality',
        'dig': 'DNS lookup functionality', 
        'curl': 'HTTP requests and API calls',
        'jq': 'JSON processing',
        'whatweb': 'Web technology detection',
        'exiftool': 'Metadata extraction'
    }
    
    # Check Python modules (always required)
    missing_modules = []
    required_modules = ['requests', 'dnspython', 'rich', 'questionary']
    
    for module in required_modules:
        try:
            __import__(module.replace('dnspython', 'dns'))
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print_error("Missing required Python modules:")
        for module in missing_modules:
            console.print(f"  [red]❌ {module}[/red]")
        console.print("\n[yellow]Install with: pip install -r requirements.txt[/yellow]")
        return False
    
    print_success("All required Python modules are available!")
    
    # Check optional external tools
    missing_tools = []
    available_tools = []
    
    for tool, description in optional_tools.items():
        if shutil.which(tool):
            available_tools.append((tool, description))
        else:
            missing_tools.append((tool, description))
    
    if available_tools:
        print_info("Available external tools:")
        for tool, desc in available_tools:
            console.print(f"  [green]✅ {tool}[/green] - {desc}")
    
    if missing_tools:
        print_warning("Optional tools not found (some features may use fallbacks):")
        for tool, desc in missing_tools:
            console.print(f"  [yellow]⚠️  {tool}[/yellow] - {desc}")
        
        if sys.platform.startswith('win'):
            console.print("\n[cyan]Windows users:[/cyan]")
            console.print("• Many features work without external tools")
            console.print("• For full functionality, consider installing Git for Windows (includes curl)")
            console.print("• ExifTool can be downloaded from: https://exiftool.org/")
        else:
            console.print("\n[yellow]Install missing tools with:[/yellow]")
            if sys.platform.startswith('linux'):
                console.print("[cyan]sudo apt update && sudo apt install whois dnsutils curl jq whatweb exiftool[/cyan]")
            elif sys.platform.startswith('darwin'):
                console.print("[cyan]brew install whois bind curl jq whatweb exiftool[/cyan]")
    
    # Always return True since we have fallbacks for Windows
    return True

def format_json_output(json_str):
    """Format JSON output for better readability"""
    import json
    try:
        data = json.loads(json_str)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except:
        return json_str

def create_progress_bar(description="Processing"):
    """Create a reusable progress bar"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

def animate_text(text, delay=0.05):
    """Animate text output character by character"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def clear_screen():
    """Clear the terminal screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_for_enter():
    """Wait for user to press Enter"""
    console.print("\n[dim]Press Enter to continue...[/dim]", end="")
    input()

def print_separator(char="─", length=80, style="dim"):
    """Print a visual separator line"""
    console.print(char * length, style=style)
