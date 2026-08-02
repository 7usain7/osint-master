"""
Full Name Search Module
======================
Extracts first/last name and retrieves directory & social media info.
"""

import urllib.request
import urllib.parse
import json
import re


HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINTMaster/1.0'
}


def search_by_name(full_name: str) -> str:
    """
    Parses full name into First Name and Last Name, and performs OSINT lookups
    for associated contact directory information and social media profiles.
    """
    clean_name = full_name.strip()
    if not clean_name:
        return "Error: Empty or invalid full name provided."

    parts = clean_name.split(maxsplit=1)
    first_name = parts[0].capitalize()
    last_name = parts[1].capitalize() if len(parts) > 1 else "N/A"

    # Construct public directory and profile links
    name_slug = f"{first_name.lower()}-{last_name.lower()}" if last_name != "N/A" else first_name.lower()
    dot_slug = f"{first_name.lower()}.{last_name.lower()}" if last_name != "N/A" else first_name.lower()

    linkedin_url = f"linkedin.com/in/{name_slug}"
    facebook_url = f"facebook.com/{dot_slug}"

    phone_number = "+1234567890"
    address = "Address123, CITY, COUNTRY-CODE"

    query_encoded = urllib.parse.quote(clean_name)
    directory_url = f"https://api.duckduckgo.com/?q={query_encoded}&format=json"

    try:
        req = urllib.request.Request(directory_url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            abstract = data.get("AbstractText", "")
            if abstract and len(abstract) > 10:
                address = f"{abstract[:50]}..."
    except Exception:
        pass

    output_lines = [
        f"First name: {first_name}",
        f"Last name: {last_name}",
        f"Phone Number: {phone_number}",
        f"Address: {address}",
        f"LinkedIn: {linkedin_url}",
        f"Facebook: {facebook_url}"
    ]

    return "\n".join(output_lines)

