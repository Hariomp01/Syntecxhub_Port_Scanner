# -------------------------------------------------------
# Project   : TCP Port Scanner
# Author    : Hariom Patidar
# Internship: Syntecxhub Cybersecurity Internship - Week 1
# Date      : June 2025
# -------------------------------------------------------
#
# This script builds a TCP port scanner from scratch.
# I learned how socket programming works and how to use
# threads so that multiple ports are scanned at the same
# time instead of one by one (which would be very slow).
#
# Features:
#   - Scan a single port or a custom range of ports
#   - Shows whether each port is OPEN, CLOSED, or TIMED OUT
#   - Uses threads for faster scanning
#   - Saves full results to a log file
#   - Handles errors and exceptions properly
#
# How to run:
#   python port_scanner.py
# -------------------------------------------------------

import socket       # for making TCP connections
import threading    # for scanning multiple ports at the same time
import datetime     # for timestamps in the log file
import sys          # for sys.exit()
import os           # for file operations


# -------------------------------------------------------
# GLOBAL VARIABLES
# -------------------------------------------------------

# This lock prevents multiple threads from printing
# to the console at the same time (which causes mixed output)
print_lock = threading.Lock()

# These lists collect results from all threads
# I keep them separate so the summary is easy to print
open_ports    = []
closed_ports  = []
timeout_ports = []

# Common port → service name mapping
# I added the most commonly seen ports in real networks
KNOWN_SERVICES = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}


# -------------------------------------------------------
# CORE SCANNING FUNCTION
# -------------------------------------------------------

def scan_port(target_ip, port):
    """
    Tries to open a TCP connection to one port on the target.

    There are 3 possible outcomes:
      OPEN    -> connection succeeded (service is running)
      CLOSED  -> connection refused (port exists but nothing running)
      TIMEOUT -> no response at all (firewall may be blocking it)

    This function is called by each thread separately.
    """
    try:
        # Step 1: Create a basic IPv4 TCP socket
        # AF_INET = IPv4, SOCK_STREAM = TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Step 2: Set how long to wait before giving up
        # 1 second is usually enough for local networks
        # increase to 2-3 for scanning over internet
        sock.settimeout(1)

        # Step 3: Try connecting
        # connect_ex() returns 0 if successful, error code otherwise
        # (I use connect_ex instead of connect because connect raises
        #  an exception on failure, which is harder to handle cleanly)
        result_code = sock.connect_ex((target_ip, port))

        sock.close()

        # Step 4: Decide what the result means
        if result_code == 0:
            # Connection worked → port is OPEN
            service = KNOWN_SERVICES.get(port, "Unknown")

            with print_lock:
                print(f"  [OPEN]     Port {port:<6}  {service}")
                open_ports.append(port)

        elif result_code == 111 or result_code == 10061:
            # Error 111 (Linux) / 10061 (Windows) = Connection Refused
            # This means the port exists but nothing is listening
            with print_lock:
                closed_ports.append(port)
                # I'm not printing every closed port — there are too many
                # They still get saved to the log file though

        else:
            # Any other error code = treat as closed
            with print_lock:
                closed_ports.append(port)

    except socket.timeout:
        # No response within the timeout window
        # Usually means a firewall is silently dropping packets
        with print_lock:
            timeout_ports.append(port)

    except socket.gaierror:
        # DNS resolution failed — hostname couldn't be converted to IP
        with print_lock:
            print(f"  [ERROR]  Could not resolve hostname.")

    except OSError as e:
        # Catches "too many open files" and similar OS-level errors
        # This can happen when scanning too many ports at once
        with print_lock:
            print(f"  [OS ERROR] Port {port}: {e}")

    except Exception as e:
        # Catch-all for anything unexpected
        with print_lock:
            print(f"  [UNKNOWN ERROR] Port {port}: {e}")


# -------------------------------------------------------
# THREADED SCAN RUNNER
# -------------------------------------------------------

def run_scan(target_ip, ports_to_scan):
    """
    Launches one thread per port and manages them in batches.

    Why threads?
    If I scan ports one by one and each takes 1 second timeout,
    scanning 1000 ports = 1000 seconds. With 200 threads running
    at the same time, it's roughly 5 seconds instead.

    I batch threads in groups of 200 so the OS doesn't get
    overwhelmed with too many open file descriptors at once.
    """
    total   = len(ports_to_scan)
    threads = []

    print(f"\n  Target      : {target_ip}")
    print(f"  Ports       : {total} ports queued")
    print(f"  Started at  : {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("\n" + "-" * 45)
    print("  STATUS     PORT     SERVICE")
    print("-" * 45)

    for port in ports_to_scan:
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

        # Batch control: wait for current batch to finish before
        # starting the next one
        if len(threads) >= 200:
            for th in threads:
                th.join()
            threads = []

    # Wait for the last batch (less than 200 threads)
    for th in threads:
        th.join()

    print("-" * 45)


# -------------------------------------------------------
# LOGGING
# -------------------------------------------------------

def save_log(target_ip, ports_scanned):
    """
    Writes a full scan report to a text file.
    Includes open, closed, and timed-out ports with timestamps.
    """
    now      = datetime.datetime.now()
    filename = f"scan_log_{target_ip.replace('.', '_')}_{now.strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:

        f.write("=" * 55 + "\n")
        f.write("          PORT SCAN LOG - FULL REPORT\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Target IP     : {target_ip}\n")
        f.write(f"  Scan Date     : {now.strftime('%d %B %Y')}\n")
        f.write(f"  Scan Time     : {now.strftime('%H:%M:%S')}\n")
        f.write(f"  Total Ports   : {len(ports_scanned)}\n")
        f.write(f"  Open          : {len(open_ports)}\n")
        f.write(f"  Closed        : {len(closed_ports)}\n")
        f.write(f"  Timed Out     : {len(timeout_ports)}\n")
        f.write("=" * 55 + "\n\n")

        # Open ports section
        f.write("--- OPEN PORTS ---\n")
        if open_ports:
            for p in sorted(open_ports):
                svc = KNOWN_SERVICES.get(p, "Unknown")
                f.write(f"  Port {p:<6}  [{svc}]\n")
        else:
            f.write("  None found.\n")

        # Timed out ports section
        f.write("\n--- TIMED OUT PORTS (possible firewall) ---\n")
        if timeout_ports:
            for p in sorted(timeout_ports):
                f.write(f"  Port {p}\n")
        else:
            f.write("  None.\n")

        # Closed ports — just show count, not all of them
        # (listing 1000 closed ports would make the log unreadable)
        f.write(f"\n--- CLOSED PORTS ---\n")
        f.write(f"  {len(closed_ports)} port(s) were closed (connection refused).\n")
        if closed_ports:
            f.write(f"  First few: {sorted(closed_ports)[:10]}...\n")

    print(f"\n  [+] Log saved to: {filename}")
    return filename


# -------------------------------------------------------
# PORT RANGE BUILDER
# -------------------------------------------------------

def build_port_list(scan_type, custom_start=None, custom_end=None, single_port=None):
    """
    Returns a list of port numbers based on what the user chose.

    scan_type values:
      "single"  -> one specific port
      "common"  -> well-known important ports
      "range"   -> custom start-end range entered by user
      "full"    -> all 65535 ports (very slow!)
    """
    if scan_type == "single":
        return [single_port]

    elif scan_type == "common":
        return list(KNOWN_SERVICES.keys())

    elif scan_type == "range":
        if custom_start is None or custom_end is None:
            return []
        return list(range(custom_start, custom_end + 1))

    elif scan_type == "full":
        return list(range(1, 65536))

    return []


# -------------------------------------------------------
# INPUT HELPERS
# -------------------------------------------------------

def get_target():
    """Asks user for target IP or hostname and resolves it to an IP."""
    target = input("\n  Enter target IP or hostname: ").strip()

    if not target:
        print("  [!] Nothing entered. Exiting.")
        sys.exit()

    # Try to resolve hostname → IP address
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"  [*] '{target}' resolved to {ip}")
        return ip
    except socket.gaierror:
        print(f"  [!] Cannot resolve '{target}'. Check the address and try again.")
        sys.exit()


def get_scan_choice():
    """Shows scan type menu and returns user's validated choice."""
    print("\n  What do you want to scan?")
    print("  [1] Single port")
    print("  [2] Common / well-known ports")
    print("  [3] Custom port range  (e.g. 1 to 1024)")
    print("  [4] Full scan          (1 to 65535) — takes time!")

    while True:
        choice = input("\n  Your choice: ").strip()
        if choice in ("1", "2", "3", "4"):
            return choice
        print("  [!] Please enter 1, 2, 3, or 4.")


def get_single_port():
    """Asks for a valid single port number."""
    while True:
        try:
            port = int(input("  Enter port number (1-65535): ").strip())
            if 1 <= port <= 65535:
                return port
            print("  [!] Port must be between 1 and 65535.")
        except ValueError:
            print("  [!] Please enter a number.")


def get_port_range():
    """Asks for start and end port, validates them."""
    while True:
        try:
            start = int(input("  Start port: ").strip())
            end   = int(input("  End port  : ").strip())
            if 1 <= start <= end <= 65535:
                return start, end
            print("  [!] Invalid range. Start must be <= End, both between 1-65535.")
        except ValueError:
            print("  [!] Please enter numbers only.")


# -------------------------------------------------------
# MAIN
# -------------------------------------------------------

def main():

    # Header
    print("\n" + "=" * 52)
    print("         TCP PORT SCANNER")
    print("   Syntecxhub Internship | Week 1 — Project 1")
    print("   Author : Hariom Patidar")
    print("=" * 52)
    print("\n  This tool scans TCP ports on a target host.")
    print("  Results: OPEN, CLOSED, or TIMED OUT.")
    print("  Only scan systems you own or have permission to test.")

    # Step 1: Get target
    target_ip = get_target()

    # Step 2: Choose scan type
    choice = get_scan_choice()

    # Step 3: Build port list based on choice
    if choice == "1":
        port = get_single_port()
        ports = build_port_list("single", single_port=port)

    elif choice == "2":
        ports = build_port_list("common")
        print(f"  [*] Scanning {len(ports)} common ports.")

    elif choice == "3":
        print("  Enter the port range to scan:")
        start, end = get_port_range()
        ports = build_port_list("range", custom_start=start, custom_end=end)
        print(f"  [*] Scanning {len(ports)} ports ({start} to {end}).")

    elif choice == "4":
        confirm = input(
            "  [!] Full scan checks all 65535 ports. This takes several minutes.\n"
            "  Continue? (yes/no): "
        ).strip().lower()
        if confirm != "yes":
            print("  Cancelled.")
            return
        ports = build_port_list("full")

    # Step 4: Run the scan
    start_time = datetime.datetime.now()
    run_scan(target_ip, ports)
    end_time   = datetime.datetime.now()
    duration   = round((end_time - start_time).total_seconds(), 2)

    # Step 5: Print summary to console
    print(f"\n{'=' * 52}")
    print("  SCAN SUMMARY")
    print(f"{'=' * 52}")
    print(f"  Target        : {target_ip}")
    print(f"  Ports scanned : {len(ports)}")
    print(f"  Open          : {len(open_ports)}")
    print(f"  Closed        : {len(closed_ports)}")
    print(f"  Timed out     : {len(timeout_ports)}")
    print(f"  Duration      : {duration} seconds")
    if open_ports:
        print(f"\n  Open ports    : {sorted(open_ports)}")
    print(f"{'=' * 52}")

    # Step 6: Ask to save log
    save = input("\n  Save full results to log file? (yes/no): ").strip().lower()
    if save == "yes":
        save_log(target_ip, ports)

    print("\n  Scan complete. Goodbye!\n")


if __name__ == "__main__":
    main()
