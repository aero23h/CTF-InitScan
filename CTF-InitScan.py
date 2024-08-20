import argparse
import socket
import time
import nmap
import sys
import itertools
import threading
import subprocess


class TerminalColors(object):

    def __init__(self, color=True):
        if color:
            self.BLUE = '\033[94m'
            self.CYAN = '\033[96m'
            self.GREEN = '\033[92m'
            self.ORANGE = '\x1b[38;2;240;127;29m'
            self.RED = '\033[91m'
            self.END = '\033[0m'
        else:
            self.BLUE = self.CYAN = self.GREEN = self.ORANGE = self.RED = self.END = ""

# runs nmap scan and prints the result depending on the arguments
def nmap_scan(arguments):
    nmap_args = arguments.nmap_args

    if not nmap_args:
        nmap_args = []

    conditional_print(f"\nRunning nmap scan on {arguments.target} with the arguments: {' '.join(nmap_args)}", quiet=arguments.quiet)
    nm = nmap.PortScanner()

    print("\n")
    stop_event = threading.Event()
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event, "nmap"))
    animation_thread.start()

    try:
        scan_results = nm.scan(arguments.target, arguments=' '.join(nmap_args))
    finally:
        stop_event.set()
        animation_thread.join()

    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                service = port_info.get('name', 'Unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                extrainfo = port_info.get('extrainfo', '')
                scripts = port_info.get('script', {})

                service_info = f"{service} {product} {version} {extrainfo}".strip()
                print(f"\n\tPort : {port}\tState : {port_info['state']}\tService : {service_info}")

            if scripts:
                for script_name, script_output in scripts.items():
                    print(f"\t{script_name}: {script_output}")

    return nm, scan_results

# quick check for available web-ports
def check_web_ports(arguments):
    ports = [80, 443, 8080, 8888, 1234]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((arguments.target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    # check for manually added port
    if arguments.add_port: open_ports.extend(arguments.add_port)

    if open_ports:
        for port in open_ports:
            if port in arguments.add_port:
                conditional_print(f"Manually added port: {port}", quiet=arguments.quiet)
            else:
                conditional_print(f"Open web-port found at http://{arguments.target}:{port}", quiet=arguments.quiet)
    else:
        conditional_print(f"No open web-ports found on {arguments.target}.", quiet=arguments.quiet)

    return open_ports

# loading animation for better look while scanning
def loading_animation(stop_event, service):
    animation = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{service} is running ' + next(animation))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write(f'\r{service} is running.. complete!\n')

# print only if condition set. Used for argument -q
def conditional_print(*args, **kwargs):
    if not kwargs.pop('quiet', False):
        print(*args, **kwargs)

def show_nmap_help():
    print(subprocess.run(['nmap', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout)

def show_dirsearch_help():
    print(subprocess.run(['dirsearch', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout)

def show_ffuf_help():
    print(subprocess.run(['ffuf', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout)

# runs dirsearch scans for all open web-ports in separate terminals, depending on the arguments
def run_dirsearch(arguments, ports):
    for port in ports:
        if isinstance(arguments.dirsearch, list) and len(arguments.dirsearch) > 0:
            command = ["dirsearch", "-u", f"http://{arguments.target}:{port}/"] + arguments.dirsearch
        else:
            command = ["dirsearch", "-u", f"http://{arguments.target}:{port}/", "-e", "php,html,txt,"]

        conditional_print(f"Running command: {' '.join(command)}", quiet=arguments.quiet)

        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{' '.join(command)}; exec bash"])

# runs ffuf scans for all open web-ports in separate terminals, depending on the arguments
def run_subdomain_ffuf(arguments, ports):
    for port in ports:
        if isinstance(arguments.ffuf, list) and len(arguments.ffuf) > 0:
            command = [f"ffuf -u http://{arguments.target}:{port}", "-H", f"HOST:FUZZ.{arguments.target}"] + arguments.ffuf_args
        else:
            default_wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
            command = ["ffuf", "-w", default_wordlist, "-u", f"http://{arguments.target}:{port}", "-H", f"HOST:FUZZ.{arguments.target}","-c", "-mc 200 -ac"]

        conditional_print(f"Running command: {' '.join(command)}", quiet=arguments.quiet)

        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{' '.join(command)}; exec bash"])

#just a nice ascii-art :)
def ascii_art():
    colors = TerminalColors(True)
    return colors.BLUE + '  _____ _______ ______    _____       _ _    _____                 \n' \
                         ' / ____|__   __|  ____|  |_   _|     (_) |  / ____|                \n' \
                         '| |       | |  | |__ ______| |  _ __  _| |_| (___   ___ __ _ _ __  \n' \
                         '| |       | |  |  __|______| | | \'_ \\| | __|\\___ \\ / __/ _` | \'_ \\ \n' \
                         '| |____   | |  | |        _| |_| | | | | |_ ____) | (_| (_| | | | |\n' \
                         ' \\_____|  |_|  |_|       |_____|_| |_|_|\\__|_____/ \\___\\__,_|_| |_|\n' + colors.END

# if user has not previously specified whether he wants to use ffuf or dirsearch,
# he will be asked and the selected operations will be added to the thread list
def ask_user_for_scans(arguments, ports):
    options = {
        'f': 'ffuf',
        'd': 'dirsearch',
        'fd': 'both',
        'n': 'none'
    }

    threads = []

    print("\nOpen Web-Ports found. Which scan do you want to perform?\n(with presets) ")
    print("f: Ffuf (subdomain scan)")
    print("d: Dirsearch (directories and file scan)")
    print("fd: both (Ffuf and Dirsearch)")
    print("n: none")

    choice = input("Choose an option: ")

    while choice not in options:
        choice = input("Invalid selection. Please select f, d, fd or n: ")

    if options[choice] == 'ffuf':
        ffuf_thread = threading.Thread(target=run_subdomain_ffuf, args=(arguments,ports))
        threads.append(ffuf_thread)
    elif options[choice] == 'dirsearch':
        ds_thread = threading.Thread(target=run_dirsearch, args=(arguments,ports))
        threads.append(ds_thread)
    elif options[choice] == 'both':
        ffuf_thread = threading.Thread(target=run_subdomain_ffuf, args=(arguments,ports))
        ds_thread = threading.Thread(target=run_dirsearch, args=(arguments,ports))
        threads.append(ffuf_thread)
        threads.append(ds_thread)

    print("\n")
    return threads

def main():
    print(ascii_art())
    arguments = parse_args()
    threads = []
    open_web_ports = check_web_ports(arguments)

    if len(open_web_ports) > 0:
        if isinstance(arguments.ffuf, list):
            ffuf_thread = threading.Thread(target=run_subdomain_ffuf, args=(arguments, open_web_ports))
            threads.append(ffuf_thread)

        if isinstance(arguments.dirsearch, list):
            ds_thread = threading.Thread(target=run_dirsearch, args=(arguments, open_web_ports))
            threads.append(ds_thread)

        if not isinstance(arguments.ffuf, list) and not isinstance(arguments.dirsearch, list):
            threads.extend(ask_user_for_scans(arguments, open_web_ports))

    if not arguments.no_nmap:
        nmap_thread = threading.Thread(target=nmap_scan, args=(arguments,))
        threads.append(nmap_thread)
    else:
        conditional_print("\nSkipping nmap scan as --no-nmap was provided.", quiet=arguments.quiet)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

def parse_args():
    parser = argparse.ArgumentParser(description='CTF-InitScan')
    parser.add_argument("-nh", "--nmap-help", action="store_true", help="show Nmap help message and exit")
    parser.add_argument("-dsh", "--dirsearch-help", action="store_true", help="show Dirsearch help message and exit")
    parser.add_argument("-fh", "--ffuf-help", action="store_true", help="show Fuff help message and exit")
    parser.add_argument('target', type=str, help='bare URL or IP')
    parser.add_argument("-n", "--nmap_args", nargs="*", help='specifying nmap-arguments')
    parser.add_argument("-f", "--ffuf", nargs="*",help="running Ffuf if possible "
                                                       "(optional with custom arguments)")
    parser.add_argument("-ds", "--dirsearch", nargs="*", help="running dirsearch if possible "
                                                              "(optional with custom arguments)")
    parser.add_argument("--no-nmap", action="store_true", help="Skip Nmap scan")
    parser.add_argument('-q', '--quiet', action='store_true', help='suppress unnecessary output')
    parser.add_argument("-p", "--add_port", nargs="*", help='add a extra port to scan')
    args, unknown = parser.parse_known_args()

    if args.nmap_help:
        show_nmap_help()
        sys.exit()

    if args.dirsearch_help:
        show_dirsearch_help()
        sys.exit()

    if args.ffuf_help:
        show_ffuf_help()
        sys.exit()

    return args

if __name__ == "__main__":
    main()
