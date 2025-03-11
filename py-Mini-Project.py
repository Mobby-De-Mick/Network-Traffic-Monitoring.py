import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

# Constants
THRESHOLD = 40  # Packet rate threshold for blocking
print(f"THRESHOLD: {THRESHOLD}")

# Function to read IP addresses from a file
def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file if line.strip()]
        return set(ips)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Using empty set.")
        return set()

# Function to detect Nimda worm traffic
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet[TCP].payload:
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload
    return False

# Function to log events
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, "log.txt")

    with open(log_file, "a") as file:
        file.write(f"{timestamp} - {message}\n")

# Callback function to process each packet
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Check whitelist
    if src_ip in whitelist_ips:
        return

    # Check blacklist
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    # Detect Nimda worm
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    # Rate-based blocking
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in list(packet_count.items()):
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

# Main script
if __name__ == "__main__":
    # Check platform and permissions
    if sys.platform == "win32":
        print("This script is not supported on Windows.")
        sys.exit(1)
    elif os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Read whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    # Initialize variables
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring Network Traffic...")
    sniff(filter="ip", prn=packet_callback, store=False)