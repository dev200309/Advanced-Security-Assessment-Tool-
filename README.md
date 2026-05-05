# Advanced Security Assessment Tool (ASAT) v1.0

**ASAT v1.0** is a powerful, modular, multi-phase automated security assessment tool designed for Network, Subdomain, Web Application, API, and Cloud vulnerability testing. Features advanced 5-phase reconnaissance, nmapAutomator-integrated network sweeping, OWASP Top 10 mapping, and detailed JSON/Text/HTML reporting. Happy Hacking! 🚀

---

## Prerequisites

The tool requires **Python 3** and the following dependencies to function properly.
Furthermore, the system requires `nmap` and standard recon tools (like `ffuf`, `nikto`, `smbclient`) for advanced network and service scanning.

### 1. Install System Dependencies

```bash
# For Debian/Ubuntu-based systems
sudo apt update
sudo apt install nmap -y

# Optional but highly recommended for Phase 1 (Network) service recon
sudo apt install ffuf gobuster nikto sslscan smtp-user-enum smbmap smbclient enum4linux snmp joomscan wpscan
```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt
# OR manually:
pip3 install python-nmap requests dnspython whois colorama beautifulsoup4
```

---

## Usage Guide

Because the script utilizes raw sockets and SYN scanning features of `nmap`, it must be run with **Root/Sudo privileges**.

### Basic Usage

**Run a complete scan (All Phases)** against a target:

```bash
sudo python3 happyhacking.py -t <target> --all
```

*Example:* `sudo python3 happyhacking.py -t example.com --all`

### Available Arguments

| Argument | Long Argument   | Description                                                                                                             |
| :------- | :-------------- | :---------------------------------------------------------------------------------------------------------------------- |
| `-t`   | `--target`    | **(Required)** Target domain or IP address.                                                                       |
|          | `--phase`     | Scan phase to run (`1`=Network, `2`=Subdomain, `3`=Web, `4`=API, `5`=Cloud). Can be specified multiple times. |
|          | `--all`       | Run all scan phases (`1`, `2`, `3`, `4`, and `5`).                                                            |
| `-o`   | `--output`    | Output file for the report. If not specified, a timestamped file is generated automatically.                            |
|          | `--format`    | Report format (Choices:`txt`, `json`, `html`. Default: `txt`).                                                            |
| `-v`   | `--verbose`   | Enable verbose output for more detailed logs during execution.                                                          |
|          | `--no-banner` | Suppress the banner display at startup.                                                                                 |
| `-h`   | `--help`      | Show the help message and exit.                                                                                         |

---

## 🎯 Architecture & High-Accuracy Checks

ASAT v1.0 utilizes a modular architecture (`asat/core/` and `asat/phases/`) for easy maintainability. It is engineered with strict, highly specific validation logic to eliminate false positive vulnerabilities during scans:

- **Strict Protocol Validation (SMB):** Validates precise `\xffSMB` or `\xfeSMB` magic bytes and packet length before asserting that an SMB signing vulnerability exists.
- **Definitive File Verification (HTTP PUT):** When testing for HTTP Verb tampering, instead of relying on unreliable 200/201 status codes, ASAT actively attempts to create a unique test file and verifies creation.
- **Accurate Database Error Matching (SQLi):** Meticulously matches specific backend exceptions like `"unclosed quotation mark after the character string"` or `"pg_query(): query failed"`.
- **Context-Aware Payload Reflection (XSS):** Checks the `Content-Type` headers before flagging an embedded `<script>` payload.
- **Baseline Comparison for Auth Bypasses:** Establishes a "baseline failed login" profile to flag an alert *only* if the bypass attempt triggers a different behavior.

---

## Scan Phases Explained

The tool is divided into five major scan phases that you can trigger individually or together:

### Phase 1: Network Scan (`--phase 1`)
*Powered by nmapAutomator integration*

Performs deep network reconnaissance and scanning.
- **Host Discovery & Sweep**: Ping sweeps, DNS resolution, TTL-based OS detection, and /24 subnet discovery.
- **Port Scanning**: Comprehensive `SYN` scan using `nmap` (1-65535 ports), automatically falling back to `-Pn` if ICMP is blocked.
- **UDP Scanning**: Scans top UDP ports and runs service scripts.
- **Vulnerability Checks**: Automated CVE scans (`vulners.nse`) and `nmap --script vuln`.
- **Service-Specific Recon**: Automatically triggers deeper enumeration based on open ports:
  - **SMB**: `smbmap`, `smbclient`, `enum4linux`
  - **SMTP**: `smtp-user-enum`
  - **LDAP**: Anonymous bind checks via `ldapsearch`
  - **Web**: Directory fuzzing (`ffuf`/`gobuster`), SSL checks (`sslscan`), vulnerability scanning (`nikto`), and CMS enumeration (`wpscan`, `joomscan`, `droopescan`)
- **Firewall/IDS Detection**: Inconsistent port states inspection.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 1`

### Phase 2: Subdomain Scan (`--phase 2`)
Performs subdomain discovery and analysis.
- Connects to sources like DNS zone transfers and bruteforce mechanisms to find mapped assets.
- Checks for potential subdomain takeover risks.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 2`

### Phase 3: Web Application Scan (`--phase 3`)
Performs active and passive web vulnerability checks.
- Checks for advanced Injections: SQL Injection (SQLi), Server-Side Template Injection (SSTI), OS Command Injection (Time & Output based), Cross-Site Scripting (XSS), SSRF, and Path Traversal.
- Performs rigorous Authentication Bypass attempts (SQLi, Default Credentials, Rate Limiting/Lockout checks).
- Validates misconfigurations: Missing security headers, exposed sensitive info/admin panels (with exact HTTP status codes), clickjacking, and file uploads.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 3`

### Phase 4: API Security Scan (`--phase 4`)
Targets hidden and undocumented API routes (OWASP API Security Top 10).
- **JWT Security Analysis**: Detects `alg:none`, weak secrets, expired tokens, missing claims.
- **GraphQL Introspection**: Detects if GraphQL introspection is enabled causing data leaks.
- **BOLA/IDOR Testing**: Tests sequential ID access patterns.
- **API Rate Limiting & CORS**: Tests for brute-force risks and deep CORS credential reflection.
- **Mass Assignment**: Tests if APIs accept extra fields for privilege escalation.
- **Endpoint Discovery**: Hunts for publicly exposed documentation files like `swagger.json` and `openapi.yaml`, and API Key Leakage.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 4`

### Phase 5: Cloud Infrastructure & Bucket Hunting (`--phase 5`)
Reconnaissance layer hunting for misconfigured public cloud storage across multiple providers.
- **AWS S3**: Dynamically searches for poorly-secured AWS S3 buckets (e.g. `target-backup.s3.amazonaws.com`).
- **Azure Blob Storage**: Hunts for `*.blob.core.windows.net` containers.
- **GCP Storage**: Hunts for `storage.googleapis.com` buckets.
- **Firebase & DigitalOcean**: Checks for open Firebase databases (`*.firebaseio.com`) and Spaces.
- Assesses and reports if any discovered buckets allow unauthorized public directory listing or SSRF via Cloud Metadata.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 5`

### Combining Phases

You can combine multiple phases if you don't want to run all of them:

```bash
sudo python3 happyhacking.py -t example.com --phase 1 --phase 3
```

---

## Reporting

ASAT v1.0 generates professional reports (including CVSS scoring mapped to vulnerabilities). By default, the tool outputs a `.txt` report file with a timestamp in the current directory if run successfully.
You can format it as JSON, HTML, or specify a custom filename.

**Save as JSON format:**
```bash
sudo python3 happyhacking.py -t example.com --all --format json -o output_report.json
```

**Save as a specific Text file:**
```bash
sudo python3 happyhacking.py -t example.com --all -o scan_results.txt
```

---

> ⚠️ **DISCLAIMER:** This tool is for authorized security testing only! Unauthorized use against systems you don't own is illegal! By using this tool, you agree to use it responsibly and ethically.
