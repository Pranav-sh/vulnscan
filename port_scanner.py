import socket
import concurrent.futures

# Define common sensitive ports
sensitive_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

# Function to check if a port is open
def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port, True
            else:
                return port, False
    except socket.error as e:
        return port, False

# Function to scan ports
def scan_ports(ip, ports):
    active_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(check_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                port, is_open = future.result()
                if is_open:
                    active_ports[port] = sensitive_ports.get(port, "Unknown Service")
            except Exception as exc:
                print(f"Port {port} generated an exception: {exc}")
    return active_ports

# Validate IP address
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Validate hostname
def is_valid_hostname(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

# Main function
def main():
    ip = input("Enter the IP address or hostname to scan: ")
    
    if not is_valid_ip(ip) and not is_valid_hostname(ip):
        print("Invalid IP address or hostname. Please try again.")
        return
    
    print(f"Scanning {ip} for active and sensitive ports...")
    active_ports = scan_ports(ip, sensitive_ports.keys())
    if active_ports:
        print("Active and sensitive ports found:")
        for port, service in active_ports.items():
            print(f"Port {port}: {service}")
    else:
        print("No active and sensitive ports found.")

if __name__ == "__main__":
    main()
