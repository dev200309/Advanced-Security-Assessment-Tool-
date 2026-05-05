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

class Colors:
    """Color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ProgressIndicator:
    """Simple progress indicator for long-running tasks"""
    def __init__(self, total, description="Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.lock = threading.Lock()
        self.start_time = time.time()
        
    def update(self, amount=1):
        with self.lock:
            self.current += amount
            self._display()
    
    def _display(self):
        percentage = (self.current / self.total) * 100
        elapsed = time.time() - self.start_time
        bar_length = 40
        filled = int(bar_length * self.current // self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        sys.stdout.write(f'\r{PROGRESS} {self.description}: [{bar}] {percentage:.1f}% ({self.current}/{self.total}) - {elapsed:.1f}s')
        sys.stdout.flush()
        if self.current >= self.total:
            print()

class RiskRating:
    """Risk rating classifications"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @staticmethod
    def color(rating):
        colors = {
            RiskRating.CRITICAL: Fore.RED + Back.BLACK + Style.BRIGHT,
            RiskRating.HIGH: Fore.RED,
            RiskRating.MEDIUM: Fore.YELLOW,
            RiskRating.LOW: Fore.BLUE,
            RiskRating.INFO: Fore.WHITE
        }
        return colors.get(rating, Fore.WHITE)

class Finding:
    """Class to store individual findings"""
    def __init__(self, title, description, risk_rating, remediation, phase):
        self.title = title
        self.description = description
        self.risk_rating = risk_rating
        self.remediation = remediation
        self.phase = phase
        self.timestamp = datetime.datetime.now().isoformat()
        self.evidence = []
    
    def add_evidence(self, evidence):
        self.evidence.append(evidence)
    
    def to_dict(self):
        return {
            'title': self.title,
            'description': self.description,
            'risk_rating': self.risk_rating,
            'remediation': self.remediation,
            'phase': self.phase,
            'timestamp': self.timestamp,
            'evidence': self.evidence
        }
    
    def __str__(self):
        color = RiskRating.color(self.risk_rating)
        return f"{color}[{self.risk_rating}]{Style.RESET_ALL} {self.title}\n    Description: {self.description}\n    Remediation: {self.remediation}"

class Report:
    """Class to handle report generation"""
    def __init__(self, target):
        self.target = target
        self.start_time = datetime.datetime.now()
        self.findings = []
        self.scan_summary = defaultdict(int)
        
    def add_finding(self, finding):
        self.findings.append(finding)
        self.scan_summary[finding.risk_rating] += 1
    
    def generate_text_report(self):
        """Generate a formatted text report"""
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        
        report = []
        report.append("=" * 80)
        report.append(f"SECURITY ASSESSMENT REPORT - {self.target}")
        report.append(f"Scan started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Scan ended: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total duration: {duration}")
        report.append("=" * 80)
        report.append("\n")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        total_findings = len(self.findings)
        report.append(f"Total findings: {total_findings}")
        report.append(f"Critical: {self.scan_summary.get(RiskRating.CRITICAL, 0)}")
        report.append(f"High: {self.scan_summary.get(RiskRating.HIGH, 0)}")
        report.append(f"Medium: {self.scan_summary.get(RiskRating.MEDIUM, 0)}")
        report.append(f"Low: {self.scan_summary.get(RiskRating.LOW, 0)}")
        report.append(f"Info: {self.scan_summary.get(RiskRating.INFO, 0)}")
        report.append("\n")
        
        # Findings by Phase
        phases = ['Network', 'Subdomain', 'Web', 'API', 'Cloud']
        for phase in phases:
            phase_findings = [f for f in self.findings if f.phase == phase]
            if phase_findings:
                report.append(f"\n{phase.upper()} PHASE FINDINGS")
                report.append("-" * 40)
                for finding in phase_findings:
                    color = RiskRating.color(finding.risk_rating)
                    report.append(f"\n{color}[{finding.risk_rating}]{Style.RESET_ALL} {finding.title}")
                    report.append(f"  Description: {finding.description}")
                    if finding.evidence:
                        report.append("  Evidence:")
                        for evidence in finding.evidence[:3]:  # Limit evidence
                            report.append(f"    - {evidence}")
                    report.append(f"  Remediation: {finding.remediation}")
        
        return "\n".join(report)
    
    def generate_json_report(self):
        """Generate JSON report"""
        return json.dumps({
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.datetime.now().isoformat(),
            'summary': dict(self.scan_summary),
            'findings': [f.to_dict() for f in self.findings]
        }, indent=2)

    def generate_html_report(self):
        """Generate a beautiful, interactive HTML report that can be printed to PDF."""
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        
        # Calculate summary numbers
        total = len(self.findings)
        critical = self.scan_summary.get(RiskRating.CRITICAL, 0)
        high = self.scan_summary.get(RiskRating.HIGH, 0)
        medium = self.scan_summary.get(RiskRating.MEDIUM, 0)
        low = self.scan_summary.get(RiskRating.LOW, 0)
        info = self.scan_summary.get(RiskRating.INFO, 0)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASAT Report: {self.target}</title>
    <style>
        :root {{
            --bg: #0f111a;
            --surface: #1a1d27;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #2d3748;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #475569;
            --accent: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        header {{
            border-bottom: 2px solid var(--accent);
            padding-bottom: 2rem;
            margin-bottom: 2rem;
            text-align: center;
        }}
        h1 {{ color: var(--accent); font-size: 2.5rem; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 0.5rem; }}
        .meta-info {{ color: var(--text-muted); font-family: monospace; font-size: 0.95rem; }}
        .summary-dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 3rem;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .stat-value {{ font-size: 2.5rem; font-weight: bold; margin-bottom: 0.5rem; }}
        .stat-label {{ text-transform: uppercase; font-size: 0.8rem; font-weight: 600; letter-spacing: 1px; color: var(--text-muted); }}
        
        .val-total {{ color: var(--text); }}
        .val-critical {{ color: var(--critical); }}
        .val-high {{ color: var(--high); }}
        .val-medium {{ color: var(--medium); }}
        .val-low {{ color: var(--low); }}
        .val-info {{ color: var(--info); }}
        
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 5px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            page-break-inside: avoid;
        }}
        .finding-header {{
            padding: 1.2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0,0,0,0.2);
        }}
        .finding-title {{ font-size: 1.2rem; font-weight: 600; color: var(--text); }}
        .badge {{
            padding: 0.3rem 0.8rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #fff;
        }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); }}
        .badge.low {{ background: var(--low); }}
        .badge.info {{ background: var(--info); }}
        
        .border-critical {{ border-left-color: var(--critical); }}
        .border-high {{ border-left-color: var(--high); }}
        .border-medium {{ border-left-color: var(--medium); }}
        .border-low {{ border-left-color: var(--low); }}
        .border-info {{ border-left-color: var(--info); }}
        
        .finding-body {{ padding: 1.5rem; }}
        .section-title {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 0.5rem; font-weight: bold; }}
        .finding-section {{ margin-bottom: 1.5rem; }}
        .finding-section:last-child {{ margin-bottom: 0; }}
        p {{ color: var(--text); font-size: 0.95rem; }}
        ul {{ list-style-position: inside; color: var(--text); font-size: 0.95rem; padding-left: 1rem; }}
        li {{ margin-bottom: 0.25rem; font-family: monospace; }}
        
        .phase-header {{
            margin: 3rem 0 1.5rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        /* Print Styles for PDF */
        @media print {{
            body {{ background: #ffffff; color: #000000; }}
            .stat-card, .finding-card {{ box-shadow: none; border-color: #e2e8f0; background: #f8fafc; }}
            .finding-header {{ background: #f1f5f9; }}
            .meta-info, .stat-label, .section-title, p, ul {{ color: #334155; }}
            .val-total {{ color: #0f172a; }}
            h1 {{ color: #dc2626; }}
            .phase-header {{ color: #dc2626; border-bottom-color: #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ASAT Security Report</h1>
            <div class="meta-info">
                Target: {self.target}<br>
                Scan Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}<br>
                Duration: {duration}
            </div>
        </header>

        <div class="summary-dashboard">
            <div class="stat-card">
                <div class="stat-value val-total">{total}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value val-critical">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value val-high">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value val-medium">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value val-low">{low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
"""

        # Generate findings by phase
        phases = ['Network', 'Subdomain', 'Web', 'API', 'Cloud']
        for phase in phases:
            phase_findings = [f for f in self.findings if f.phase == phase]
            if not phase_findings:
                continue
                
            html += f'<h2 class="phase-header">{phase} Phase</h2>\n'
            
            for finding in phase_findings:
                risk_lower = finding.risk_rating.lower()
                
                # Format evidence list
                evidence_html = ""
                if finding.evidence:
                    evidence_items = "".join([f"<li>{e}</li>" for e in finding.evidence[:5]])
                    evidence_html = f"""
                    <div class="finding-section">
                        <div class="section-title">Evidence</div>
                        <ul>{evidence_items}</ul>
                    </div>"""

                html += f"""
        <div class="finding-card border-{risk_lower}">
            <div class="finding-header">
                <div class="finding-title">{finding.title}</div>
                <span class="badge {risk_lower}">{finding.risk_rating}</span>
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <div class="section-title">Description</div>
                    <p>{finding.description}</p>
                </div>
                {evidence_html}
                <div class="finding-section">
                    <div class="section-title">Remediation</div>
                    <p>{finding.remediation}</p>
                </div>
            </div>
        </div>
"""

        html += """
    </div>
</body>
</html>"""
        return html


