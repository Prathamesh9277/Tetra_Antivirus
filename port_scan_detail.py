import psutil
import os
import threading
import tkinter as tk
from tkinter import messagebox
import time
from scapy.all import sniff, IP, TCP #network packet capturing library other pyshark and pcapy
# Mapping of standard ports to their associated services
import subprocess 
traffic_lock = threading.Lock()
standard_ports_services = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    67: "DHCP (Dynamic Host Configuration Protocol) Server",
    68: "DHCP Client",
    69: "TFTP (Trivial File Transfer Protocol)",
    80: "HTTP (HyperText Transfer Protocol)",
    110: "POP3 (Post Office Protocol 3)",
    111: "RPC (Remote Procedure Call)",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Network Time Protocol)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    443: "HTTPS (HyperText Transfer Protocol Secure)",
    445: "SMB (Server Message Block)",
    465: "SMTP over SSL",
    514: "Syslog",
    587: "SMTP (Submission)",
    631: "IPP (Internet Printing Protocol)",
    636: "LDAP over SSL",
    873: "rsync",
    993: "IMAP over SSL",
    995: "POP3 over SSL",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Server (UDP)",
    2049: "NFS (Network File System)",
    2375: "Docker (HTTP)",
    2376: "Docker (HTTPS)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL",
    5672: "AMQP (Advanced Message Queuing Protocol)",
    5900: "VNC (Virtual Network Computing)",
    5984: "CouchDB",
    6379: "Redis",
    8000: "HTTP Alternate",
    8080: "HTTP Alternate (Proxy)",
    8443: "HTTPS Alternate",
    9000: "HTTP Alternate (often used by PHP-FPM)",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

WHITELISTED_PROCESSES = {
    'chromium',
    'firefox-bin',
    'python',
    'chrome',
    'firefox',
    'opera',
    'safari',
    'sshd',
    'ssh',
    'gnome-terminal',
    'xterm',
    'filezilla',
    'vscode',
    'mysqld',
    'postgres',
    'mongod',
    'python3',
    'java',
    'node',
    'git',
    'vlc',
    'mpv',
    'rhythmbox',
}


ports = list(standard_ports_services.keys())
services = list(standard_ports_services.values())
secure_ports = []
suspicious_ports1 = []
TRANSFER_THRESHOLD = 1024 * 1024
LOGIN_ATTEMPT_THRESHOLD = 5
LOGIN_TIME_WINDOW = 10
BLCKLISTED_IP = {}
login_attempts = {}
suspicious_ports2 = {}
traffic_data = {}


def drop_connection(src_ip, dst_port , dst_ip):
    """Send a TCP RST packet to drop the connection."""
    # require to put the systems IP , but IP changes every day , even if i make another funtion to get the system IP it requres roots permission thats why 
    rst_packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='R', sport=RandShort())
    send(rst_packet)
    print(f"Connection dropped: Source IP {src_ip}, Destination Port {dst_port}")

def suspecius_port_scan():
    global secure_ports, suspicious_ports1  # Declare globals at the top of the function
    active_ports = []
    # Clear previous results
    secure_ports.clear()
    suspicious_ports1.clear()

    for conn in psutil.net_connections(kind="inet"):
        pid = conn.pid
        process_name = psutil.Process(pid).name() if pid else "N/A"
        local_port = conn.laddr.port
        local_service = standard_ports_services.get(local_port, "Unknown")
        active_ports.append((local_port, local_service))
    
        if local_port in ports and local_service != "Unknown":
            expected_service = standard_ports_services[local_port]
            if local_service == expected_service:
                secure_ports.append((local_port, local_service, process_name))
            else:
                if process_name not in WHITELISTED_PROCESSES:
                    suspicious_ports1.append((local_port, local_service, process_name))
        else:
            if process_name not in WHITELISTED_PROCESSES:
                suspicious_ports1.append((local_port, local_service, process_name))
    # Optional debug print

    # print("secure ports:")
    # print(secure_ports)

    # print("suspicious ports: ")
    # print(suspicious_ports1)

    return suspicious_ports1 
suspecius_port_scan()

def drop_connection(src_ip, dst_port , dst_ip):
    """Send a TCP RST packet to drop the connection."""
    # require to put the systems IP , but IP changes every day , even if i make another funtion to get the system IP it requres roots permission thats why 
    rst_packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='R', sport=RandShort())
    send(rst_packet)
    print(f"Connection dropped: Source IP {src_ip}, Destination Port {dst_port}")

def handle_permission_error(e):
    """Handles permission errors by showing a message box in the main thread."""
    global permission_error_occurred
    response = messagebox.askyesno("Permission Error", f"Permission denied: {e}. Do you want to run this application with elevated privileges?")
    if response:
        script_name = os.path.abspath(__file__)
        subprocess.run(["sudo", "python3", script_name], check=True)

def sniff_traffic(filter_func, bpf_filter):
    #"""Function to sniff traffic using a specific filter function."""
        port_list = [str(port) for port, _ , _ in suspicious_ports1]
        #this is porper systax understand the syntax of the filter  _____IMPORTANT_________ 
# Possible Causes:
# Incorrect BPF Syntax: The BPF filter syntax expects the keyword port without a colon : before the port number. So instead of port:80, 
# it should be port 80. The colon syntax (port:80) is incorrect for BPF filters, which is why it's failing to compile.
# Too Many Ports in a Single Filter: If the filter contains too many ports, 
# it might exceed the size or complexity that the underlying packet capture engine (like libpcap) can handle. This could also lead to failure in compiling the filter.
        bpf_filter = " or ".join([f"port {port}" for port in port_list])
        global permission_error_occurred, error_message
        try:
            sniff(prn=packet_handler, store=0, filter=bpf_filter)
        except PermissionError as e:
            permission_error_occurred = True  # Set the flag for permission error
            error_message = str(e) 
            handle_permission_error(error_message)

def packet_handler(packet):
    """Filter packets based on login attempts and update suspicious_ports2."""
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_port = tcp_layer.dport
        dst_ip = ip_layer.dst
        if src_ip in BLCKLISTED_IP:
            drop_connection(src_ip, dst_port)

        # Handle login attempt monitoring
        if src_ip not in login_attempts:
            login_attempts[src_ip] = {'attempts': 0, 'first_attempt_time': time.time()}
        
        login_attempts[src_ip]['attempts'] += 1
        elapsed_time = time.time() - login_attempts[src_ip]['first_attempt_time']

        if elapsed_time <= LOGIN_TIME_WINDOW and login_attempts[src_ip]['attempts'] > LOGIN_ATTEMPT_THRESHOLD:
            print(f"Alert: Possible brute force detected from {src_ip}, {login_attempts[src_ip]['attempts']} attempts")
            BLCKLISTED_IP[src_ip] = True  # Blacklist the IP

            # Add suspicious port to suspicious_ports2
            if src_ip not in suspicious_ports2:
                suspicious_ports2[src_ip] = []
            if dst_port not in suspicious_ports2[src_ip]:
                suspicious_ports2[src_ip].append(dst_port)
        else:
            # Reset the login attempts after time window expires
            login_attempts[src_ip]['attempts'] = 0
            login_attempts[src_ip]['first_attempt_time'] = time.time()

def drop_packet(ip , port):
    try:
        command = f"iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP"
        print(f"Packet drooped: blocked IP {ip} on port {port}")
        subprocess.run(command, shell=True , check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to drop packet: {e}")

def monitor_traffic():
    """Periodically check traffic data and take action if suspicious activity is detected."""
    global traffic_data
    while True:
        time.sleep(60)  # Check every minute
        with traffic_lock:
            for traffic_key, data in traffic_data.items():
                if data['bytes'] > TRANSFER_THRESHOLD:
                    print(f"Alert: Suspicious data transfer detected on port {traffic_key[0]} with {data['bytes']} bytes")
                    drop_packet("IP_TO_BLOCK", traffic_key[0])  # Replace with actual IP if needed
                    data['bytes'] = 0  # Reset the byte count
                else:
                    print("No suspicious traffic detected.")
                data['last_check'] = time.time()

def start_monitoring():
    global traffic_data 
    # Call function to scan for suspicious ports
    suspicious_ports = suspecius_port_scan()
    print("Suspicious Ports:", suspicious_ports)

    # Assuming suspicious_ports is a list of tuples/lists, ensure the unpacking is valid
    traffic_data = {(port, service): {'bytes': 0, 'last_check': time.time()} for port, service, _ in suspicious_ports1} 
    port_list = [str(port) for port, _, _ in suspicious_ports1]
    bpf_filter = " or ".join([f"port {port}" for port in port_list])
    
    # Start the traffic monitoring in a separate thread
    monitoring_thread = threading.Thread(target=monitor_traffic)
    monitoring_thread.daemon = True  # Daemonize thread
    monitoring_thread.start()

    # Start the traffic sniffing in another thread
    sniffing_thread = threading.Thread(target=sniff_traffic, args=(packet_handler, bpf_filter))
    sniffing_thread.daemon = True  # Daemonize thread
    sniffing_thread.start()


def main():
    # Initialize your Tkinter GUI
    root = tk.Tk()
    root.withdraw()
    root.title("Network Monitoring Tool")
    
    # Start monitoring when the GUI is loaded
    start_monitoring()
    
    # Set up your Tkinter GUI layout here
    
    root.mainloop()  # Start the GUI event loop

