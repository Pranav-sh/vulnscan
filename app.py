from flask import Flask, request, render_template, jsonify
from src.scanner import scan_ports
from src.banner_grabber import grab_banner
from src.vuln_scanner import check_vulnerabilities
from src.network_mapper import discover_devices
from src.os_fingerprinting import os_fingerprinting
from src.report import generate_report
from src.utils import parse_banner

app = Flask(__name__)

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form['ip']
    subnet = request.form['subnet']

    # Scan ports
    open_ports = scan_ports(ip, sensitive_ports.keys())

    # Grab banners
    banners = {port: grab_banner(ip, port) for port in open_ports}

    # Check vulnerabilities
    vulnerabilities = {}
    for port, banner in banners.items():
        service, version = parse_banner(banner)
        vulnerabilities[port] = check_vulnerabilities(service, version)

    # Map network
    devices = discover_devices(subnet)

    # OS Fingerprinting
    os_info = os_fingerprinting(ip)

    # Generate report
    report_filename = 'report.csv'
    generate_report(ip, open_ports, vulnerabilities, report_filename)

    return render_template('results.html', open_ports=open_ports, banners=banners, vulnerabilities=vulnerabilities, devices=devices, os_info=os_info, report_filename=report_filename)

if __name__ == "__main__":
    app.run(debug=True)
