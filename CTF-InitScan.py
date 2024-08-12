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
    scan_results = nm.scan(target, arguments=' '.join(arguments))
    return nm, scan_results


# quick check for available web-ports
def check_web_ports(target):
    ports = [80, 443]
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
    else:
        print(f"No open web-ports found on {target} .")


def loading_animation(stop_event):
    animation = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write('\rScan is running ' + next(animation))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rScan is running.. complete!\n')


def show_nmap_help():
    result = subprocess.run(['nmap', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(result.stdout)


def main(target, nmap_args):
    # check für argument -h
    if '-h' in nmap_args:
        print("\nHelp for CTF-InitScan:\n" + "-"*60)
        parser.print_help()

        print("\nHelp for nmap:\n" + "-"*60)
        show_nmap_help()
        sys.exit()

    check_web_ports(target)

    print(f"\nRunning nmap scan on {target} with the arguments: {' '.join(nmap_args)}")

    # create thread for loading animation
    stop_event = threading.Event()

    # start loading animation in separate thread
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    animation_thread.start()

    try:
        nm, scan_results = nmap_scan(target, nmap_args)
    except nmap.PortScannerError as e:
        print(f"\nAn error occurred during the nmap scan: {e}")
        stop_event.set()
        animation_thread.join()
        sys.exit(1)

    stop_event.set()
    animation_thread.join()

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CTF-InitScan')
    parser.add_argument('target', type=str, help='address or ip')
    parser.add_argument('nmap_args', nargs=argparse.REMAINDER, help='nmap-arguments')

    args = parser.parse_args()
    main(args.target, args.nmap_args)
