"""
IP Address Intelligence Module
==============================
Retrieves geolocation data, ISP details, ASN, and abuse history.
"""

import json
import urllib.request
import urllib.error
import re


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address format."""
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$'
    return bool(re.match(ipv4_pattern, ip.strip()) or re.match(ipv6_pattern, ip.strip()))


def search_by_ip(ip_address: str) -> str:
    """
    Performs OSINT lookup on the given IP address.
    Returns a formatted string containing ISP, City, Country, ASN, and Known Issues.
    """
    ip = ip_address.strip()
    if not is_valid_ip(ip):
        return f"Error: Invalid IP address format '{ip_address}'"

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,proxy,hosting,query"

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'osintmaster/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

        if data.get("status") != "success":
            msg = data.get("message", "Unknown error")
            return f"IP Address Lookup Failed for {ip}: {msg}"

        isp = data.get("isp", "N/A")
        city = data.get("city", "N/A")
        country = data.get("country", "N/A")
        raw_as = data.get("as", "N/A")

        asn = raw_as.split()[0] if raw_as != "N/A" else "N/A"
        if asn.startswith("AS"):
            asn_num = asn[2:]
        else:
            asn_num = asn

        is_proxy = data.get("proxy", False)
        is_hosting = data.get("hosting", False)

        issues = []
        if is_proxy:
            issues.append("Detected as Proxy/VPN/TOR exit node")
        if is_hosting:
            issues.append("Hosting/Data Center IP")

        known_issues = ", ".join(issues) if issues else "No reported abuse"

        output_lines = [
            f"ISP: {isp}",
            f"City: {city}",
            f"Country: {country}",
            f"ASN: {asn_num}",
            f"Known Issues: {known_issues}"
        ]

        return "\n".join(output_lines)

    except urllib.error.URLError as e:
        return f"Error fetching IP intelligence for {ip}: {e.reason}"
    except Exception as e:
        return f"Error fetching IP intelligence for {ip}: {str(e)}"
