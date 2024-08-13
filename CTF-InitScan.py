import argparse
import nmap
import socket
import sys
import time
import itertools
import threading
import subprocess


def nmap_scan(target, arguments):
    nm = nmap.PortScanner()

    # create thread for loading animation
    stop_event = threading.Event()
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event, "nmap"))
    animation_thread.start()

    try:
        scan_results = nm.scan(target, arguments=' '.join(arguments))
    finally:
        stop_event.set()
        animation_thread.join()

    return nm, scan_results


# quick check for available web-ports
def check_web_ports(target):
    ports = [80, 443, 8080, 1234]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        for port in open_ports:
            print(f"Open web-port found at http://{target}:{port}")
            return True
    else:
        print(f"No open web-ports found on {target}.")
        return False


def loading_animation(stop_event, service):
    animation = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{service} is running ' + next(animation))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write(f'\r{service} is running.. complete!\n')


def show_nmap_help():
    result = subprocess.run(['nmap', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(result.stdout)


def run_dirsearch(target_url):
    command = ["dirsearch", "-u", f"http://{target_url}/", "-e", "php,html,txt,"]

    result = subprocess.run(command)


def run_subdomain_ffuf(target_url, wordlist=None):
    if wordlist:
        command = ["ffuf", "-w", wordlist, "-u", target_url, "-H", f"HOST:FUZZ.{target_url}", "-c"]
    else:
        default_wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
        command = ["ffuf", "-w", default_wordlist, "-u", target_url, "-H", f"HOST:FUZZ.{target_url}", "-c"]

    # create thread for loading animation
    stop_event = threading.Event()
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event, "ffuf"))
    animation_thread.start()

    try:
        result = subprocess.run(command)
    finally:
        stop_event.set()
        animation_thread.join()


def main(arguments):
    # check for argument -h
    if arguments.nmap_args and '-h' in arguments.nmap_args:
        print("\nHelp for CTF-InitScan:\n" + "-"*60)
        parser.print_help()

        print("\nHelp for nmap:\n" + "-"*60)
        show_nmap_help()
        sys.exit()

    if check_web_ports(arguments.target):
        if arguments.ffuf:
            run_subdomain_ffuf(arguments.target, arguments.ffuf if isinstance(arguments.ffuf, str) else None)

        if arguments.dirsearch:
            run_dirsearch(arguments.target)

        # Check if the --no-nmap argument is set, and skip nmap if it is
        if not arguments.no_nmap:
            nmap_args = arguments.nmap_args if arguments.nmap_args is not None else []

            print(f"\nRunning nmap scan on {arguments.target} with the arguments: {' '.join(nmap_args)}")

            try:
                nm, scan_results = nmap_scan(arguments.target, nmap_args)
            except nmap.PortScannerError as e:
                print(f"\nAn error occurred during the nmap scan: {e}")
                sys.exit(1)

            print("Scan completed!\n")

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
        else:
            print("\nSkipping nmap scan as --no-nmap was provided.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CTF-InitScan')
    parser.add_argument('target', type=str, help='bare URL or IP')
    parser.add_argument("-n", "--nmap_args", nargs="*", help='nmap-arguments')
    parser.add_argument("-f", "--ffuf", nargs="?", const=True, help="running ffuf (optional: set wordlist)")
    parser.add_argument("-ds", "--dirsearch", nargs="?", const=True, help="running dirsearch")
    parser.add_argument("--no-nmap", action="store_true", help="Skip nmap scan")
    args = parser.parse_args()

    main(args)
