"""
Domain & Subdomain Enumeration Module
=====================================
Enumerates subdomains, gathers IPs, SSL details, and analyzes subdomain takeover risks.
"""

import socket
import ssl
import urllib.request
import json
import subprocess
from datetime import datetime
import concurrent.futures
import re

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINTMaster/1.0'
}

KNOWN_TAKEOVER_SERVICES = {
    's3.amazonaws.com': 'non-existent AWS S3 bucket',
    's3-website': 'non-existent AWS S3 bucket',
    'github.io': 'unclaimed GitHub Pages site',
    'herokuapp.com': 'non-existent Heroku app',
    'herokudns.com': 'non-existent Heroku app',
    'azurewebsites.net': 'unclaimed Azure website',
    'cloudapp.net': 'unclaimed Azure service',
    'cloudfront.net': 'unconfigured CloudFront distribution',
    'pantheonsite.io': 'unclaimed Pantheon site',
    'surge.sh': 'unclaimed Surge.sh site',
    'wordpress.com': 'unclaimed WordPress blog',
    'zendesk.com': 'unclaimed Zendesk instance'
}

COMMON_PREFIXES = ['www', 'mail', 'test', 'dev', 'api', 'admin', 'app', 'blog', 'stage']


def fetch_subdomains_hackertarget(domain: str) -> set:
    """Fetch subdomains from HackerTarget hostsearch API."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


def fetch_subdomains_crtsh(domain: str) -> set:
    """Fetch subdomains from crt.sh Certificate Transparency logs."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for entry in data:
                name_value = entry.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name.startswith('*.'):
                        name = name[2:]
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


def resolve_ip(hostname: str) -> str:
    """Resolve IP address for hostname."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def get_ssl_info(hostname: str) -> str:
    """Fetch SSL certificate validity date."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert['notAfter']
                dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                return f"Valid until {dt.strftime('%Y-%m-%d')}"
    except Exception:
        return "Not found"


def get_cname(hostname: str) -> str:
    """Query CNAME record for hostname."""
    try:
        res = subprocess.run(['host', '-t', 'CNAME', hostname], capture_output=True, text=True, timeout=3)
        if 'an alias for' in res.stdout:
            return res.stdout.split('an alias for')[-1].strip().rstrip('.')
    except Exception:
        pass
    try:
        real_name, aliases, _ = socket.gethostbyname_ex(hostname)
        for alias in aliases:
            if alias != hostname:
                return alias
        if real_name != hostname:
            return real_name
    except Exception:
        pass
    return None


def analyze_subdomain(subdomain: str) -> dict:
    """Gather IP, SSL info, and takeover risk for a single subdomain."""
    ip = resolve_ip(subdomain)
    ssl_info = get_ssl_info(subdomain) if ip else "Not found"
    cname = get_cname(subdomain)
    
    takeover_risk = None
    if cname:
        for pattern, service_name in KNOWN_TAKEOVER_SERVICES.items():
            if pattern in cname.lower():
                cname_ip = resolve_ip(cname)
                if not cname_ip:
                    takeover_risk = {
                        'subdomain': subdomain,
                        'cname_details': f"CNAME record points to a {service_name}",
                        'action': "Remove or update the DNS record to prevent potential misuse"
                    }
                break

    return {
        'subdomain': subdomain,
        'ip': ip,
        'ssl': ssl_info,
        'cname': cname,
        'takeover_risk': takeover_risk
    }


def search_by_domain(domain_input: str) -> str:
    """
    Performs OSINT domain enumeration, IP resolution, SSL inspection,
    and subdomain takeover analysis.
    """
    clean_domain = domain_input.strip().lower()
    clean_domain = re.sub(r'^https?://', '', clean_domain).split('/')[0]

    if not clean_domain:
        return "Error: Invalid domain name provided."

    # Discover subdomains from multiple sources
    discovered = set()
    discovered.update(fetch_subdomains_hackertarget(clean_domain))
    discovered.update(fetch_subdomains_crtsh(clean_domain))

    # Add common subdomains
    for prefix in COMMON_PREFIXES:
        discovered.add(f"{prefix}.{clean_domain}")

    # Remove apex domain from subdomain list if present, but ensure unique sorted subdomains
    subdomains_to_check = sorted(list(discovered))

    # Process subdomains concurrently
    subdomain_results = []
    takeover_risks = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyze_subdomain, sub): sub for sub in subdomains_to_check}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            # Only include subdomains that resolve or have CNAME records
            if res['ip'] or res['cname'] or res['subdomain'] in [f"www.{clean_domain}", f"mail.{clean_domain}", f"test.{clean_domain}"]:
                subdomain_results.append(res)
            if res['takeover_risk']:
                takeover_risks.append(res['takeover_risk'])

    # Sort results predictably
    subdomain_results.sort(key=lambda x: x['subdomain'])

    output_lines = [
        f"Main Domain: {clean_domain}",
        "",
        f"Subdomains found: {len(subdomain_results)}"
    ]

    for item in subdomain_results:
        ip_str = f" (IP: {item['ip']})" if item['ip'] else " (IP: Unresolved)"
        output_lines.append(f"  - {item['subdomain']}{ip_str}")
        output_lines.append(f"    SSL Certificate: {item['ssl']}")

    if takeover_risks:
        output_lines.append("")
        output_lines.append("Potential Subdomain Takeover Risks:")
        for risk in takeover_risks:
            output_lines.append(f"  - Subdomain: {risk['subdomain']}")
            output_lines.append(f"    {risk['cname_details']}")
            output_lines.append(f"    Recommended Action: {risk['action']}")

    return "\n".join(output_lines)
