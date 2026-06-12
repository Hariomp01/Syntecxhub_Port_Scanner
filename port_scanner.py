# -------------------------------------------------------
# Project  : TCP Port Scanner
# Author   : Hariom Patidar
# Internship: Syntecxhub Cybersecurity Internship - Week 1
# Date     : June 2025
# -------------------------------------------------------
# What this does:
#   - Takes a target IP/hostname from the user
#   - Scans ports using TCP connect method
#   - Uses threads to scan multiple ports at the same time
#   - Shows open ports and tries to guess the service name
#   - Saves results to a log file
# -------------------------------------------------------

import socket
import threading
import datetime
import sys
import os

# I'm using a lock so that when multiple threads try to
# print at the same time, output doesn't get mixed up
print_lock = threading.Lock()

# Storing all open ports here so I can print a summary at the end
open_ports = []

# Some common ports and their service names
# I looked these up from standard port assignments
SERVICE_NAMES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017:"MongoDB"
}


def scan_single_port(target_ip, port):
    """
    This function tries to connect to one port.
    If connection succeeds -> port is OPEN
    If connection refused or timeout -> port is CLOSED or FILTERED
    """
    try:
        # Creating a basic TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Setting timeout so we don't wait forever on filtered ports
        sock.settimeout(1)

        # connect_ex returns 0 if connection was successful
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            # Port is open! Let's find out what service it might be
            service = SERVICE_NAMES.get(port, "Unknown Service")

            # Using lock before printing so output stays clean
            with print_lock:
                print(f"  [OPEN]  Port {port:>5}  -->  {service}")
                open_ports.append(port)

    except socket.error as e:
        # Something went wrong with the socket itself
        # This is rare but good to handle
        pass

    except Exception as e:
        pass


def scan_ports(target_ip, port_list):
    """
    Scans a list of ports using multiple threads.
    I'm using threading here because scanning ports one by one
    would be very slow — threading lets us scan many at the same time.
    """
    threads = []

    print(f"\n  Starting scan on: {target_ip}")
    print(f"  Total ports to scan: {len(port_list)}")
    print(f"  Scan started at: {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("\n" + "-" * 45)
    print("  OPEN PORTS FOUND:")
    print("-" * 45)

    for port in port_list:
        # Creating a new thread for each port
        t = threading.Thread(target=scan_single_port, args=(target_ip, port))
        threads.append(t)
        t.start()

        # I limit to 200 threads at a time so the system doesn't crash
        # Once we hit 200, we wait for all of them to finish before continuing
        if len(threads) >= 200:
            for thread in threads:
                thread.join()
            threads = []

    # Wait for any remaining threads to complete
    for thread in threads:
        thread.join()


def save_results_to_file(target_ip, ports_scanned):
    """
    Saves scan results to a .txt log file.
    File name includes the IP and timestamp so it's easy to find later.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"scan_{target_ip.replace('.', '_')}_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("       PORT SCAN RESULTS\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target IP   : {target_ip}\n")
        f.write(f"Scan Time   : {datetime.datetime.now()}\n")
        f.write(f"Ports Checked: {len(ports_scanned)}\n")
        f.write(f"Open Ports  : {len(open_ports)}\n")
        f.write("-" * 50 + "\n\n")

        if open_ports:
            f.write("OPEN PORTS:\n")
            for p in sorted(open_ports):
                service = SERVICE_NAMES.get(p, "Unknown")
                f.write(f"  Port {p:<6} - {service}\n")
        else:
            f.write("No open ports found.\n")

    print(f"\n  [+] Results saved to: {filename}")
    return filename


def get_port_range(choice):
    """
    Returns a list of ports based on what the user selected.
    Option 1 = common/important ports only
    Option 2 = all ports from 1 to 1024
    Option 3 = full scan (1 to 65535) — this takes a while!
    """
    if choice == "1":
        return list(SERVICE_NAMES.keys())

    elif choice == "2":
        return list(range(1, 1025))

    elif choice == "3":
        print("\n  [!] Warning: Full scan (65535 ports) will take several minutes.")
        confirm = input("  Are you sure? (y/n): ").strip().lower()
        if confirm == "y":
            return list(range(1, 65536))
        else:
            print("  Okay, going back to menu.")
            return None

    else:
        print("  Invalid choice.")
        return None


def main():
    # Header
    print("\n" + "=" * 50)
    print("       TCP PORT SCANNER")
    print("  Syntecxhub Internship | Week 1 Project 1")
    print("  Author: Hariom Patidar")
    print("=" * 50)

    # Get target from user
    target = input("\n  Enter target IP or hostname: ").strip()
    if not target:
        print("  [!] No target entered. Exiting.")
        sys.exit()

    # Try to resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        if target_ip != target:
            print(f"  [*] Resolved '{target}' to {target_ip}")
    except socket.gaierror:
        print(f"  [!] Could not resolve hostname: {target}")
        sys.exit()

    # Show scan options
    print("\n  Select port range to scan:")
    print("  [1] Common ports only (recommended for quick scan)")
    print("  [2] Well-known ports (1 - 1024)")
    print("  [3] Full scan (1 - 65535) — takes longer")

    choice = input("\n  Your choice: ").strip()
    ports  = get_port_range(choice)

    if ports is None:
        sys.exit()

    # Run the scan
    start_time = datetime.datetime.now()
    scan_ports(target_ip, ports)
    end_time = datetime.datetime.now()

    # Summary
    duration = (end_time - start_time).seconds
    print("\n" + "=" * 45)
    print("  SCAN SUMMARY")
    print("=" * 45)
    print(f"  Target      : {target_ip}")
    print(f"  Ports Scanned: {len(ports)}")
    print(f"  Open Ports  : {len(open_ports)}")
    print(f"  Time Taken  : {duration} seconds")
    if open_ports:
        print(f"  Open List   : {sorted(open_ports)}")
    print("=" * 45)

    # Ask if user wants to save results
    save = input("\n  Save results to file? (y/n): ").strip().lower()
    if save == "y":
        save_results_to_file(target_ip, ports)

    print("\n  Done! Goodbye.\n")


if __name__ == "__main__":
    main()
