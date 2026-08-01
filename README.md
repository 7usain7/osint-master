# OSINT-Master

OSINT-Master is a multi-functional passive reconnaissance CLI tool built in Python. It allows cybersecurity professionals, ethical hackers, and security researchers to gather publicly available intelligence based on user inputs such as **Full Names**, **IP Addresses**, **Usernames**, and **Domains**.

---

## Features

- **Full Name Search (`-n`)**: Parses first and last names, resolves public directory information, and constructs social media profile search targets.
- **IP Address Intelligence (`-i`)**: Validates IPv4/IPv6 addresses and retrieves ISP, city, country, ASN, and hosting/proxy abuse risk indicators using `ip-api.com`.
- **Username Reconnaissance (`-u`)**: Concurrently checks username presence across major social networks and public repositories (Facebook, Twitter/X, LinkedIn, Instagram, GitHub), while extracting GitHub activity timestamps and user metadata.
- **Domain & Subdomain Enumeration (`-d`)**: Discovers subdomains via Certificate Transparency (`crt.sh`) and HackerTarget APIs, resolves IP addresses, checks SSL certificate expiration dates, and evaluates DNS CNAME records for potential **Subdomain Takeover** risks (e.g. dangling AWS S3 buckets, GitHub Pages, Heroku apps).
- **Output Management (`-o`)**: Formats results clearly on standard output and optionally exports them to designated text files.

---

## Prerequisites

- **Python**: Version `3.8` or higher installed.
- **Operating System**: Linux, macOS, or Windows (POSIX-compliant shell recommended).
- **Standard Library**: Built with Python standard modules (`urllib`, `socket`, `ssl`, `json`, `concurrent.futures`, `argparse`). No mandatory external package installation is required.

---

## Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/osint-master.git
   cd osint-master
   ```

2. **Verify Python installation**:
   ```bash
   python3 --version
   ```

3. *(Optional)* Install optional requirements if present:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run `osintmaster.py` with `--help` to view available options:

```bash
python3 osintmaster.py --help
```

### CLI Command Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-n`, `--name` | `"Full Name"` | Search information by full name |
| `-i`, `--ip` | `"IP Address"` | Search information by IP address |
| `-u`, `--username` | `"Username"` | Search information by username |
| `-d`, `--domain` | `"Domain"` | Enumerate subdomains and check for takeover risks |
| `-o`, `--output` | `"FileName"` | File name to save output |

---

## Examples

### 1. IP Address Lookup
```bash
python3 osintmaster.py -i 8.8.8.8 -o result_ip.txt
```
**Output**:
```text
ISP: Google LLC
City: Ashburn
Country: United States
ASN: 15169
Known Issues: Hosting/Data Center IP
Data Saved in result_ip.txt
```

### 2. Username Reconnaissance
```bash
python3 osintmaster.py -u "@torvalds" -o result_username.txt
```
**Output**:
```text
Facebook: Not Found
Twitter: Found
LinkedIn: Not Found
Instagram: Found
GitHub: Found
Recent Activity: Active on GitHub, last post 10 days ago
Data Saved in result_username.txt
```

### 3. Domain & Subdomain Enumeration
```bash
python3 osintmaster.py -d "example.com" -o result_domain.txt
```
**Output**:
```text
Main Domain: example.com

Subdomains found: 3
  - www.example.com (IP: 93.184.216.34)
    SSL Certificate: Valid until 2026-09-30
  - mail.example.com (IP: Unresolved)
    SSL Certificate: Not found
  - test.example.com (IP: Unresolved)
    SSL Certificate: Not found

Potential Subdomain Takeover Risks:
  - Subdomain: test.example.com
    CNAME record points to a non-existent AWS S3 bucket
    Recommended Action: Remove or update the DNS record to prevent potential misuse
Data Saved in result_domain.txt
```

### 4. Full Name Lookup
```bash
python3 osintmaster.py -n "John Doe" -o result_name.txt
```

---

## Ethical and Legal Guidelines

- **Get Explicit Permission**: Always obtain proper authorization before gathering information or conducting security assessments.
- **Respect Privacy**: Collect only information relevant to your security scope and store data securely.
- **Comply with Laws**: Adhere strictly to cybersecurity laws and data privacy regulations, including **GDPR** and the **Computer Fraud and Abuse Act (CFAA)**.
- **Responsible Disclosure**: Privately report any identified security vulnerabilities (such as subdomain takeovers) to target asset owners.
- **Educational Use Only**: This tool is provided solely for educational purposes and authorized defensive reconnaissance.

> ⚠️ **Disclaimer**: The author assumes no liability and is not responsible for any misuse or damage caused by this program.

---

## License

This project is proprietary. The code is publicly visible for portfolio and viewing purposes only. No unauthorized copying, modification, or distribution is permitted. See [License](LICENSE) for details.

