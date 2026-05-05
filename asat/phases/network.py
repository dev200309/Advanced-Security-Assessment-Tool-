import argparse
import socket
import ssl
import json
import re
import sys
import time
import datetime
import ipaddress
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional, Any
import warnings
warnings.filterwarnings('ignore')

# Third-party imports
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    import dns.resolver
    import dns.zone
    import dns.query
    from dns.exception import DNSException
    
    import whois
    
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    
    import nmap
    
    from bs4 import BeautifulSoup
    
except ImportError as e:
    print(f"[!] Missing required dependency: {e}")
    print("[!] Please install: pip install python-nmap requests dnspython whois colorama beautifulsoup4")
    sys.exit(1)


from asat.core.config import *
from asat.core.models import *

class NetworkScanner:
    """Phase 1: Network reconnaissance and scanning (powered by nmapAutomator techniques)"""
    
    def __init__(self, target, report, verbose=False):
        self.target = re.sub(r'^https?://', '', target).split('/')[0]
        self.report = report
        self.verbose = verbose
        self.resolved_ips = []
        self.open_ports = []
        self.udp_ports = []
        self.os_type = "Unknown"
        self.is_pingable = True
        self.subnet = ""
        
    def run(self):
        """Execute all network scan phases (nmapAutomator-enhanced)"""
        print(f"\n{INFO} Starting Phase 1: Network Scan on {self.target}")
        
        # Host Discovery + TTL-based OS Detection
        self.host_discovery()
        
        # Network Sweep (live hosts in /24)
        self.network_sweep()
        
        # Port Scanning (TCP)
        self.port_scan()
        
        # Banner Grabbing
        self.grab_banners()
        
        # UDP Scan
        self.udp_scan()
        
        # CVE / Vulnerability Script Scan
        self.vuln_scan()
        
        # Network Information
        self.network_info()
        
        # Vulnerability Checks (service-specific)
        self.vulnerability_checks()
        
        # Service-Specific Recon (SMTP, SMB, LDAP, SNMP, Web, etc.)
        self.service_recon()
        
        # Firewall Detection
        self.firewall_detection()
        
        print(f"{SUCCESS} Phase 1 completed")
    
    def host_discovery(self):
        """Discover host, resolve DNS, and detect OS via TTL (nmapAutomator-style)"""
        print(f"\n{INFO} Host Discovery & TTL-based OS Detection")
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(self.target)
            self.resolved_ips.append(ip)
            print(f"{SUCCESS} Resolved {self.target} -> {ip}")
            
            # Calculate subnet for network sweep
            octets = ip.split('.')
            self.subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0"
            
            # Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                print(f"{SUCCESS} Reverse DNS: {ip} -> {hostname}")
            except Exception:
                print(f"{WARNING} No reverse DNS record found")
            
            # Ping + TTL-based OS detection (from nmapAutomator checkPing/checkOS)
            print(f"{PROGRESS} Checking if host is alive...")
            response = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                    capture_output=True, text=True)
            if response.returncode == 0:
                self.is_pingable = True
                print(f"{SUCCESS} Host is alive (responds to ping)")
                
                # Extract TTL for OS detection
                ttl_match = re.search(r'ttl=(\d+)', response.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if 0 < ttl <= 64:
                        self.os_type = "Linux"
                    elif 64 < ttl <= 128:
                        self.os_type = "Windows"
                    elif 128 < ttl <= 255:
                        self.os_type = "OpenBSD/Cisco/Oracle"
                    print(f"{SUCCESS} TTL={ttl} -> Host is likely running {self.os_type}")
                    
                    finding = Finding(
                        "OS Detection via TTL",
                        f"Target {self.target} ({ip}) TTL={ttl}, likely {self.os_type}",
                        RiskRating.INFO,
                        "N/A - This is informational",
                        "Network"
                    )
                    self.report.add_finding(finding)
                
                finding = Finding(
                    "Host is reachable",
                    f"Target {self.target} ({ip}) responds to ICMP ping",
                    RiskRating.INFO,
                    "N/A - This is informational",
                    "Network"
                )
                self.report.add_finding(finding)
            else:
                self.is_pingable = False
                print(f"{WARNING} Host does not respond to ping (will use -Pn for nmap scans)")
                
        except socket.gaierror:
            print(f"{CRITICAL} Could not resolve hostname")
            finding = Finding(
                "DNS Resolution Failed",
                f"Could not resolve hostname: {self.target}",
                RiskRating.MEDIUM,
                "Verify the target domain exists and is properly configured",
                "Network"
            )
            self.report.add_finding(finding)
    
    def port_scan(self):
        """Perform comprehensive port scan using nmap"""
        print(f"\n{INFO} Port Scanning (this may take a while...)")
        
        try:
            nm = nmap.PortScanner()
            
            # Build nmap arguments (use -Pn if host doesn't respond to ping, like nmapAutomator)
            pn_flag = '-Pn' if not self.is_pingable else ''
            scan_args = f'-sS -sV -O -T4 -p 1-65535 --min-rate 1000 --open {pn_flag}'.strip()
            
            # Perform SYN scan with version detection and OS fingerprinting
            print(f"{PROGRESS} Performing SYN scan on ports 1-65535 (nmapAutomator Full mode)...")
            nm.scan(self.target, arguments=scan_args)
            
            for host in nm.all_hosts():
                print(f"\n{SUCCESS} Host: {host}")
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'unknown')
                        version = nm[host][proto][port].get('version', '')
                        
                        port_info = f"{port}/{proto} - {state} - {service} {version}"
                        
                        if state == 'open':
                            print(f"{SUCCESS} {port_info}")
                            self.open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version
                            })
                            
                            # Check if it's a dangerous port
                            if int(port) in DANGEROUS_PORTS:
                                finding = Finding(
                                    f"Dangerous port open: {port}",
                                    f"Port {port} ({service}) is open. This service is known to have security risks.",
                                    RiskRating.HIGH if port in [21,23,445,3389] else RiskRating.MEDIUM,
                                    f"Close the port if not needed. If required, ensure it's properly secured and behind firewall.",
                                    "Network"
                                )
                                finding.add_evidence(f"Service: {service}, Version: {version}")
                                self.report.add_finding(finding)
                                
                        elif state == 'filtered':
                            print(f"{WARNING} {port_info}")
                        else:
                            if self.verbose:
                                print(f"{INFO} {port_info}")
                
                # OS Detection
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        print(f"{INFO} OS Detection: {osmatch['name']} ({osmatch['accuracy']}% accuracy)")
                    
        except Exception as e:
            print(f"{WARNING} Port scan failed: {str(e)}")
    
    def grab_banners(self):
        """Grab banners from open ports using raw sockets"""
        print(f"\n{INFO} Banner Grabbing")
        
        for port_info in self.open_ports:
            port = port_info['port']
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, port))
                
                # Send a generic probe
                if port == 80 or port == 443:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    sock.send(b"HELP\r\n")
                elif port == 25:
                    sock.send(b"HELO test.com\r\n")
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    print(f"{SUCCESS} Banner for port {port}: {banner[:100]}")
                    port_info['banner'] = banner
                    
                    # Check for sensitive information in banner
                    if any(keyword in banner.lower() for keyword in ['root', 'admin', 'password', 'vulnerable']):
                        finding = Finding(
                            f"Sensitive information in banner on port {port}",
                            f"Service banner reveals potentially sensitive information: {banner[:200]}",
                            RiskRating.MEDIUM,
                            "Disable or modify service banners to avoid information disclosure",
                            "Network"
                        )
                        self.report.add_finding(finding)
                        
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} Could not grab banner from port {port}: {str(e)}")
    
    def network_info(self):
        """Gather network information (WHOIS, GeoIP, Traceroute)"""
        print(f"\n{INFO} Gathering Network Information")
        
        # WHOIS Lookup
        try:
            print(f"{PROGRESS} Performing WHOIS lookup...")
            w = whois.whois(self.target)
            
            print(f"{SUCCESS} WHOIS Information:")
            print(f"  Registrar: {w.registrar}")
            print(f"  Creation Date: {w.creation_date}")
            print(f"  Expiration Date: {w.expiration_date}")
            print(f"  Name Servers: {w.name_servers}")
            
            finding = Finding(
                "WHOIS Information Collected",
                f"Domain registration information gathered",
                RiskRating.INFO,
                "N/A - This is informational",
                "Network"
            )
            finding.add_evidence(f"Registrar: {w.registrar}")
            self.report.add_finding(finding)
            
        except Exception as e:
            print(f"{WARNING} WHOIS lookup failed: {str(e)}")
        
        # GeoIP Lookup (using ip-api.com)
        try:
            print(f"{PROGRESS} Performing GeoIP lookup...")
            response = requests.get(f"http://ip-api.com/json/{self.resolved_ips[0]}", timeout=10)
            if response.status_code == 200:
                geo_data = response.json()
                if geo_data['status'] == 'success':
                    print(f"{SUCCESS} GeoIP Information:")
                    print(f"  Country: {geo_data['country']}")
                    print(f"  Region: {geo_data['regionName']}")
                    print(f"  City: {geo_data['city']}")
                    print(f"  ISP: {geo_data['isp']}")
                    print(f"  Organization: {geo_data['org']}")
                    print(f"  ASN: {geo_data['as']}")
                    
                    finding = Finding(
                        "GeoIP Information",
                        f"Geolocation data for target",
                        RiskRating.INFO,
                        "N/A - This is informational",
                        "Network"
                    )
                    self.report.add_finding(finding)
        except Exception as e:
            print(f"{WARNING} GeoIP lookup failed: {str(e)}")
        
        # Traceroute
        try:
            print(f"{PROGRESS} Performing traceroute...")
            if sys.platform == "win32":
                result = subprocess.run(['tracert', '-h', '15', self.target], 
                                      capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(['traceroute', '-m', '15', self.target], 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"{SUCCESS} Traceroute completed (first 5 hops):")
                lines = result.stdout.split('\n')[:5]
                for line in lines:
                    print(f"  {line}")
        except Exception as e:
            print(f"{WARNING} Traceroute failed: {str(e)}")
    
    def vulnerability_checks(self):
        """Perform common vulnerability checks"""
        print(f"\n{INFO} Performing Vulnerability Checks")
        
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            
            # FTP anonymous login check
            if port == 21 or 'ftp' in service:
                self.check_ftp_anonymous(port_info)
            
            # Telnet check
            if port == 23 or 'telnet' in service:
                finding = Finding(
                    "Telnet Service Exposed",
                    "Telnet transmits data in cleartext and is inherently insecure",
                    RiskRating.HIGH,
                    "Replace Telnet with SSH for secure remote access",
                    "Network"
                )
                self.report.add_finding(finding)
            
            # SMB signing check
            if port == 445 or 'microsoft-ds' in service or 'smb' in service:
                self.check_smb_signing(port_info)
            
            # Default SSH port check
            if port == 22 and 'ssh' in service:
                finding = Finding(
                    "SSH on Default Port",
                    "SSH service running on default port 22",
                    RiskRating.LOW,
                    "Consider moving SSH to a non-standard port to reduce automated attacks",
                    "Network"
                )
                self.report.add_finding(finding)
    
    def check_ftp_anonymous(self, port_info):
        """Check if FTP allows anonymous login"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port_info['port']))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response:  # Password required
                sock.send(b"PASS anonymous@example.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response:  # Login successful
                    print(f"{CRITICAL} FTP anonymous login allowed on port {port_info['port']}")
                    finding = Finding(
                        "FTP Anonymous Access Allowed",
                        f"FTP server on port {port_info['port']} allows anonymous login",
                        RiskRating.HIGH,
                        "Disable anonymous FTP access and implement proper authentication",
                        "Network"
                    )
                    self.report.add_finding(finding)
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} FTP anonymous check failed: {str(e)}")
    
    def check_smb_signing(self, port_info):
        """Check if SMB signing is disabled"""
        try:
            # This is a simplified check - in reality would need SMB protocol implementation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port_info['port']))
            
            # SMB Negotiate Protocol Request (simplified)
            smb_negotiate = (
                b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x00"
            )
            sock.send(smb_negotiate)
            response = sock.recv(1024)
            sock.close()
            
            # Check response for signing flags (simplified)
            if response and len(response) > 40 and response[0:4] in [b"\xffSMB", b"\xfeSMB"]:
                if response[39] & 0x08:  # Check if SMB signing is required
                    print(f"{SUCCESS} SMB signing is enabled")
                else:
                    print(f"{CRITICAL} SMB signing appears to be disabled")
                    finding = Finding(
                        "SMB Signing Disabled",
                        f"SMB server on port {port_info['port']} does not require packet signing",
                        RiskRating.HIGH,
                        "Enable SMB signing to prevent man-in-the-middle attacks",
                        "Network"
                    )
                    self.report.add_finding(finding)
                    
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} SMB signing check failed: {str(e)}")
    
    def firewall_detection(self):
        """Detect firewall/IDS presence using nmap techniques"""
        print(f"\n{INFO} Firewall/IDS Detection")
        
        try:
            nm = nmap.PortScanner()
            
            # Use various scan types to detect firewall
            scan_types = [
                ('-sS', 'SYN scan'),
                ('-sT', 'TCP connect scan'),
                ('-sA', 'ACK scan'),
                ('-sW', 'Window scan'),
                ('-sM', 'Maimon scan')
            ]
            
            results = {}
            for scan_type, desc in scan_types:
                nm.scan(self.target, arguments=f'{scan_type} -p 80,443,22 -T4')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if port not in results:
                                results[port] = []
                            results[port].append(state)
            
            # Analyze results for firewall indicators
            firewall_detected = False
            for port, states in results.items():
                if len(set(states)) > 1:  # Different scan types show different states
                    print(f"{WARNING} Potential firewall detected on port {port}: inconsistent states {states}")
                    firewall_detected = True
            
            if firewall_detected:
                finding = Finding(
                    "Firewall/IDS Detected",
                    "Inconsistent port states across different scan types suggest firewall or IDS presence",
                    RiskRating.INFO,
                    "N/A - This information can be used to plan further testing strategies",
                    "Network"
                )
                self.report.add_finding(finding)
            else:
                print(f"{INFO} No obvious firewall/IDS detected")
                
        except Exception as e:
            print(f"{WARNING} Firewall detection failed: {str(e)}")

    # ==================== nmapAutomator-derived methods ====================

    def _run_cmd(self, cmd, timeout=120):
        """Helper: run a shell command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"{WARNING} Command timed out: {cmd[:80]}...")
            return -1, "", "timeout"
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} Command failed: {e}")
            return -1, "", str(e)

    def _tool_exists(self, tool_name):
        """Check if a CLI tool is available on the system"""
        import shutil
        return shutil.which(tool_name) is not None

    def network_sweep(self):
        """Discover live hosts in the /24 subnet (nmapAutomator networkScan)"""
        if not self.subnet or not self.resolved_ips:
            return
        print(f"\n{INFO} Network Sweep — Discovering live hosts in {self.subnet}/24")
        try:
            nm = nmap.PortScanner()
            pn_flag = '' if self.is_pingable else '-Pn'
            nm.scan(hosts=f"{self.subnet}/24",
                    arguments=f'-T4 --max-retries 1 --max-scan-delay 20 -n -sn {pn_flag}'.strip())
            live_hosts = list(nm.all_hosts())
            if live_hosts:
                print(f"{SUCCESS} Found {len(live_hosts)} live host(s):")
                for h in live_hosts[:20]:
                    print(f"  {h}")
                if len(live_hosts) > 20:
                    print(f"  ... and {len(live_hosts)-20} more")
                finding = Finding(
                    "Network Sweep — Live Hosts",
                    f"Discovered {len(live_hosts)} live host(s) in {self.subnet}/24",
                    RiskRating.INFO,
                    "N/A - This is informational",
                    "Network"
                )
                for h in live_hosts[:10]:
                    finding.add_evidence(h)
                self.report.add_finding(finding)
            else:
                print(f"{INFO} No other live hosts found in subnet")
        except Exception as e:
            print(f"{WARNING} Network sweep failed: {str(e)}")

    def udp_scan(self):
        """UDP scan on common ports (nmapAutomator UDPScan)"""
        print(f"\n{INFO} UDP Scan (top 1000 ports)")
        try:
            nm = nmap.PortScanner()
            pn_flag = '-Pn' if not self.is_pingable else ''
            nm.scan(self.target, arguments=f'-sU --max-retries 1 --open -T4 {pn_flag}'.strip())
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    if proto != 'udp':
                        continue
                    for port in nm[host][proto].keys():
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'unknown')
                        version = nm[host][proto][port].get('version', '')
                        if state == 'open':
                            print(f"{SUCCESS} UDP {port} - {service} {version}")
                            self.udp_ports.append({
                                'port': port, 'protocol': 'udp',
                                'service': service, 'version': version
                            })
            if self.udp_ports:
                udp_str = ', '.join(str(p['port']) for p in self.udp_ports)
                print(f"{SUCCESS} Open UDP ports: {udp_str}")
                # Script scan on discovered UDP ports
                print(f"{PROGRESS} Running script scan on UDP ports: {udp_str}")
                nm.scan(self.target, arguments=f'-sCVU -p {udp_str} --open {pn_flag}'.strip())
                finding = Finding(
                    "Open UDP Ports Discovered",
                    f"UDP ports open: {udp_str}",
                    RiskRating.MEDIUM,
                    "Review open UDP services; close unnecessary ones",
                    "Network"
                )
                self.report.add_finding(finding)
            else:
                print(f"{INFO} No open UDP ports found")
        except Exception as e:
            print(f"{WARNING} UDP scan failed: {str(e)}")

    def vuln_scan(self):
        """CVE and vulnerability script scan on open ports (nmapAutomator vulnsScan)"""
        if not self.open_ports:
            print(f"\n{INFO} Skipping Vuln Scan (no open TCP ports)")
            return
        ports_str = ','.join(str(p['port']) for p in self.open_ports)
        pn_flag = '-Pn' if not self.is_pingable else ''
        print(f"\n{INFO} CVE / Vulnerability Scan on ports: {ports_str}")
        try:
            nm = nmap.PortScanner()
            # CVE scan with vulners script
            print(f"{PROGRESS} Running CVE scan (vulners)...")
            nm.scan(self.target,
                    arguments=f'-sV --script vulners --script-args mincvss=7.0 -p {ports_str} --open {pn_flag}'.strip())
            cve_found = False
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        script_out = nm[host][proto][port].get('script', {})
                        for script_name, output in script_out.items():
                            if 'CVE' in output or 'VULNERABLE' in output.upper():
                                cve_found = True
                                cve_ids = re.findall(r'CVE-\d{4}-\d+', output)
                                print(f"{CRITICAL} Port {port}: {', '.join(cve_ids) if cve_ids else 'Vulnerability detected'}")
                                finding = Finding(
                                    f"CVE Vulnerability on port {port}",
                                    f"Nmap vulners detected known CVEs on port {port}",
                                    RiskRating.HIGH,
                                    "Patch or upgrade the affected service immediately",
                                    "Network"
                                )
                                for cve in cve_ids[:5]:
                                    finding.add_evidence(cve)
                                finding.add_evidence(output[:300])
                                self.report.add_finding(finding)
            if not cve_found:
                print(f"{SUCCESS} No high-severity CVEs detected via vulners")

            # Nmap vuln scripts
            print(f"{PROGRESS} Running nmap vuln scripts...")
            nm.scan(self.target,
                    arguments=f'-sV --script vuln -p {ports_str} --open {pn_flag}'.strip())
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        script_out = nm[host][proto][port].get('script', {})
                        for script_name, output in script_out.items():
                            if 'VULNERABLE' in output.upper() or 'State: VULNERABLE' in output:
                                print(f"{CRITICAL} Vuln script hit on port {port}: {script_name}")
                                finding = Finding(
                                    f"Nmap Vuln Script: {script_name} (port {port})",
                                    f"Nmap vulnerability script detected issue on port {port}",
                                    RiskRating.HIGH,
                                    "Investigate and remediate the identified vulnerability",
                                    "Network"
                                )
                                finding.add_evidence(output[:500])
                                self.report.add_finding(finding)
        except Exception as e:
            print(f"{WARNING} Vuln scan failed: {str(e)}")

    def service_recon(self):
        """Service-specific deep recon based on open ports (nmapAutomator reconRecommend)"""
        print(f"\n{INFO} Service-Specific Recon (nmapAutomator-style)")

        all_ports = self.open_ports + self.udp_ports
        port_numbers = {p['port'] for p in all_ports}
        services = {p['service'].lower() for p in all_ports}

        # --- SMTP Recon (port 25) ---
        if 25 in port_numbers or 'smtp' in services:
            self._recon_smtp()

        # --- SMB Recon (port 445/139) ---
        if 445 in port_numbers or 139 in port_numbers or 'microsoft-ds' in services:
            self._recon_smb()

        # --- LDAP Recon (port 389) ---
        if 389 in port_numbers or 'ldap' in services:
            self._recon_ldap()

        # --- SNMP Recon (UDP 161) ---
        if 161 in port_numbers or 'snmp' in services:
            self._recon_snmp()

        # --- Oracle Recon (port 1521) ---
        if 1521 in port_numbers:
            self._recon_oracle()

        # --- Web Recon (HTTP/HTTPS ports) ---
        http_ports = [p for p in all_ports if 'http' in p['service'].lower()
                      or p['port'] in (80, 443, 8080, 8443)]
        if http_ports:
            self._recon_web(http_ports)

    # ---- Individual recon helpers ----

    def _recon_smtp(self):
        """SMTP user enumeration"""
        print(f"\n{PROGRESS} SMTP Recon")
        if self._tool_exists('smtp-user-enum'):
            wordlist = '/usr/share/wordlists/metasploit/unix_users.txt'
            rc, out, _ = self._run_cmd(
                f'smtp-user-enum -U {wordlist} -t {self.target}', timeout=60)
            if rc == 0 and out:
                users = [l for l in out.splitlines() if 'exists' in l.lower()]
                if users:
                    print(f"{CRITICAL} SMTP users found: {len(users)}")
                    finding = Finding(
                        "SMTP User Enumeration",
                        f"SMTP server reveals {len(users)} valid user(s)",
                        RiskRating.HIGH,
                        "Disable VRFY/EXPN commands; restrict SMTP relay",
                        "Network"
                    )
                    for u in users[:5]:
                        finding.add_evidence(u.strip())
                    self.report.add_finding(finding)
                else:
                    print(f"{SUCCESS} No users enumerated via SMTP")
        else:
            print(f"{INFO} smtp-user-enum not installed, skipping")

    def _recon_smb(self):
        """SMB enumeration (smbclient, smbmap, enum4linux)"""
        print(f"\n{PROGRESS} SMB Recon")
        # smbmap
        if self._tool_exists('smbmap'):
            rc, out, _ = self._run_cmd(f'smbmap -H {self.target}', timeout=30)
            if rc == 0 and out:
                shares = [l for l in out.splitlines() if 'READ' in l or 'WRITE' in l]
                if shares:
                    print(f"{WARNING} Accessible SMB shares found:")
                    for s in shares[:5]:
                        print(f"  {s.strip()}")
                    finding = Finding(
                        "SMB Shares Accessible",
                        f"Found {len(shares)} accessible share(s) on {self.target}",
                        RiskRating.HIGH,
                        "Restrict SMB share permissions; disable guest access",
                        "Network"
                    )
                    for s in shares[:5]:
                        finding.add_evidence(s.strip())
                    self.report.add_finding(finding)
        # smbclient
        if self._tool_exists('smbclient'):
            rc, out, _ = self._run_cmd(
                f'smbclient -L //{self.target}/ -U guest% -N', timeout=15)
            if rc == 0 and out and 'Sharename' in out:
                print(f"{INFO} SMB share listing retrieved via smbclient")
        # enum4linux for Linux targets
        if self.os_type == "Linux" and self._tool_exists('enum4linux'):
            print(f"{PROGRESS} Running enum4linux...")
            rc, out, _ = self._run_cmd(f'enum4linux -a {self.target}', timeout=120)
            if rc == 0 and out:
                print(f"{SUCCESS} enum4linux completed ({len(out.splitlines())} lines)")
        # Windows SMB vuln check
        if self.os_type == "Windows":
            try:
                nm = nmap.PortScanner()
                pn = '-Pn' if not self.is_pingable else ''
                nm.scan(self.target, arguments=f'{pn} -p445 --script vuln')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            scripts = nm[host][proto][port].get('script', {})
                            for sn, so in scripts.items():
                                if 'VULNERABLE' in so.upper():
                                    print(f"{CRITICAL} SMB vuln: {sn}")
                                    finding = Finding(
                                        f"SMB Vulnerability: {sn}",
                                        f"Windows SMB vulnerability detected via nmap",
                                        RiskRating.CRITICAL,
                                        "Apply latest security patches; consider disabling SMBv1",
                                        "Network"
                                    )
                                    finding.add_evidence(so[:300])
                                    self.report.add_finding(finding)
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} SMB vuln nmap failed: {e}")

    def _recon_ldap(self):
        """LDAP enumeration"""
        print(f"\n{PROGRESS} LDAP Recon")
        if self._tool_exists('ldapsearch'):
            rc, out, _ = self._run_cmd(
                f'ldapsearch -x -h {self.target} -s base', timeout=30)
            if rc == 0 and out:
                print(f"{SUCCESS} LDAP base query returned data")
                # Extract naming context
                nc_match = re.search(r'rootDomainNamingContext:\s*(.+)', out)
                if nc_match:
                    base_dn = nc_match.group(1).strip()
                    print(f"{INFO} Root DN: {base_dn}")
                    finding = Finding(
                        "LDAP Anonymous Bind Allowed",
                        f"LDAP server allows anonymous queries; Root DN: {base_dn}",
                        RiskRating.HIGH,
                        "Disable anonymous LDAP binds; enforce authentication",
                        "Network"
                    )
                    self.report.add_finding(finding)
        else:
            print(f"{INFO} ldapsearch not installed, skipping")

    def _recon_snmp(self):
        """SNMP enumeration"""
        print(f"\n{PROGRESS} SNMP Recon")
        if self._tool_exists('snmp-check'):
            rc, out, _ = self._run_cmd(
                f'snmp-check {self.target} -c public', timeout=60)
            if rc == 0 and out and 'System information' in out:
                print(f"{CRITICAL} SNMP public community string accepted!")
                finding = Finding(
                    "SNMP Default Community String",
                    "SNMP service accepts default 'public' community string",
                    RiskRating.HIGH,
                    "Change default SNMP community strings; use SNMPv3 with auth",
                    "Network"
                )
                self.report.add_finding(finding)
        elif self._tool_exists('snmpwalk'):
            rc, out, _ = self._run_cmd(
                f'snmpwalk -Os -c public -v1 {self.target}', timeout=60)
            if rc == 0 and out:
                print(f"{CRITICAL} SNMP walk with public community succeeded")
                finding = Finding(
                    "SNMP Default Community String",
                    "snmpwalk succeeded with default 'public' community",
                    RiskRating.HIGH,
                    "Change default SNMP community strings; use SNMPv3",
                    "Network"
                )
                self.report.add_finding(finding)
        else:
            print(f"{INFO} snmp-check/snmpwalk not installed, skipping")

    def _recon_oracle(self):
        """Oracle DB SID guessing"""
        print(f"\n{PROGRESS} Oracle Recon")
        if self._tool_exists('odat'):
            print(f"{INFO} Running odat SID guesser...")
            rc, out, _ = self._run_cmd(
                f'odat sidguesser -s {self.target} -p 1521', timeout=120)
            if rc == 0 and out and 'found' in out.lower():
                print(f"{CRITICAL} Oracle SIDs discovered!")
                finding = Finding(
                    "Oracle SID Discovered",
                    "Oracle database SIDs were guessed successfully",
                    RiskRating.HIGH,
                    "Restrict Oracle listener access; use complex SID names",
                    "Network"
                )
                finding.add_evidence(out[:300])
                self.report.add_finding(finding)
        else:
            print(f"{INFO} odat not installed, skipping Oracle recon")

    def _recon_web(self, http_ports):
        """Web server recon: nikto, sslscan, directory fuzzing, CMS detection"""
        print(f"\n{PROGRESS} Web Server Recon")
        for port_info in http_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            is_ssl = port == 443 or 'ssl' in service or 'https' in service
            scheme = 'https' if is_ssl else 'http'
            url = f"{scheme}://{self.target}:{port}"

            # sslscan for HTTPS
            if is_ssl and self._tool_exists('sslscan'):
                print(f"{PROGRESS} sslscan on {self.target}:{port}")
                rc, out, _ = self._run_cmd(f'sslscan {self.target}:{port}', timeout=60)
                if rc == 0 and out:
                    weak = [l for l in out.splitlines()
                            if any(w in l.lower() for w in ['rc4', 'des', 'null', 'sslv', 'tlsv1.0', 'tlsv1.1'])]
                    if weak:
                        print(f"{CRITICAL} Weak SSL/TLS config on port {port}")
                        finding = Finding(
                            f"Weak SSL/TLS Configuration (port {port})",
                            f"sslscan detected weak ciphers or protocols",
                            RiskRating.HIGH,
                            "Disable weak ciphers (RC4, DES, NULL) and legacy protocols (SSLv3, TLS 1.0/1.1)",
                            "Network"
                        )
                        for w in weak[:5]:
                            finding.add_evidence(w.strip())
                        self.report.add_finding(finding)

            # nikto
            if self._tool_exists('nikto'):
                print(f"{PROGRESS} nikto on {url}")
                ssl_flag = '-ssl' if is_ssl else ''
                rc, out, _ = self._run_cmd(
                    f'nikto -host "{url}" {ssl_flag} -maxtime 120s -nointeractive',
                    timeout=150)
                if rc == 0 and out:
                    vulns = [l for l in out.splitlines() if '+ ' in l and 'OSVDB' in l]
                    if vulns:
                        print(f"{WARNING} nikto found {len(vulns)} issue(s) on port {port}")
                        finding = Finding(
                            f"Nikto Web Vulnerabilities (port {port})",
                            f"Nikto scan detected {len(vulns)} potential issue(s)",
                            RiskRating.MEDIUM,
                            "Review nikto findings and remediate identified issues",
                            "Network"
                        )
                        for v in vulns[:5]:
                            finding.add_evidence(v.strip())
                        self.report.add_finding(finding)

            # Directory fuzzing (ffuf preferred, fallback to gobuster)
            if self._tool_exists('ffuf'):
                wordlist = '/usr/share/wordlists/dirb/common.txt'
                print(f"{PROGRESS} ffuf directory scan on {url}")
                rc, out, _ = self._run_cmd(
                    f'ffuf -ic -w {wordlist} -u "{url}/FUZZ" -mc 200,301,302,403 -t 40 -s',
                    timeout=120)
                if rc == 0 and out:
                    dirs = [l.strip() for l in out.splitlines() if l.strip()]
                    if dirs:
                        print(f"{SUCCESS} ffuf found {len(dirs)} path(s) on port {port}")
                        finding = Finding(
                            f"Directories Discovered (port {port})",
                            f"Directory fuzzing found {len(dirs)} path(s)",
                            RiskRating.INFO,
                            "Review exposed paths for sensitive content",
                            "Network"
                        )
                        for d in dirs[:10]:
                            finding.add_evidence(d)
                        self.report.add_finding(finding)
            elif self._tool_exists('gobuster'):
                wordlist = '/usr/share/wordlists/dirb/common.txt'
                print(f"{PROGRESS} gobuster directory scan on {url}")
                rc, out, _ = self._run_cmd(
                    f'gobuster dir -w {wordlist} -t 30 -u "{url}" -q -k',
                    timeout=120)
                if rc == 0 and out:
                    dirs = [l.strip() for l in out.splitlines() if l.strip()]
                    if dirs:
                        print(f"{SUCCESS} gobuster found {len(dirs)} path(s)")
                        finding = Finding(
                            f"Directories Discovered (port {port})",
                            f"Gobuster found {len(dirs)} path(s)",
                            RiskRating.INFO,
                            "Review exposed paths for sensitive content",
                            "Network"
                        )
                        for d in dirs[:10]:
                            finding.add_evidence(d)
                        self.report.add_finding(finding)

        # CMS Detection via nmap http-generator
        self._recon_cms()

    def _recon_cms(self):
        """CMS-specific scanning (wpscan, joomscan, droopescan) from nmapAutomator"""
        print(f"\n{PROGRESS} CMS Detection & Scanning")
        try:
            response = requests.get(
                f"http://{self.target}", timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0"})
            content = response.text.lower()
            headers = response.headers

            # Check nmap script output or response content for CMS
            cms_detected = None
            if 'wp-content' in content or 'wordpress' in content:
                cms_detected = 'WordPress'
            elif 'joomla' in content:
                cms_detected = 'Joomla'
            elif 'drupal' in content:
                cms_detected = 'Drupal'

            generator = headers.get('X-Generator', '') or ''
            if 'wordpress' in generator.lower():
                cms_detected = 'WordPress'
            elif 'joomla' in generator.lower():
                cms_detected = 'Joomla'
            elif 'drupal' in generator.lower():
                cms_detected = 'Drupal'

            if cms_detected:
                print(f"{SUCCESS} CMS Detected: {cms_detected}")
                if cms_detected == 'WordPress' and self._tool_exists('wpscan'):
                    print(f"{PROGRESS} Running wpscan...")
                    rc, out, _ = self._run_cmd(
                        f'wpscan --url http://{self.target} --enumerate p --no-banner',
                        timeout=180)
                    if rc == 0 and out:
                        vulns = [l for l in out.splitlines() if '| [!' in l]
                        if vulns:
                            finding = Finding(
                                "WordPress Vulnerabilities",
                                f"wpscan found {len(vulns)} issue(s)",
                                RiskRating.HIGH,
                                "Update WordPress core, themes, and plugins",
                                "Network"
                            )
                            for v in vulns[:5]:
                                finding.add_evidence(v.strip())
                            self.report.add_finding(finding)
                elif cms_detected == 'Joomla' and self._tool_exists('joomscan'):
                    print(f"{PROGRESS} Running joomscan...")
                    self._run_cmd(f'joomscan --url http://{self.target}', timeout=120)
                elif cms_detected == 'Drupal' and self._tool_exists('droopescan'):
                    print(f"{PROGRESS} Running droopescan...")
                    self._run_cmd(
                        f'droopescan scan drupal -u http://{self.target}', timeout=120)
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} CMS recon failed: {e}")
