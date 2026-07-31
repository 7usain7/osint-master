"""
Username Reconnaissance Module
===============================
Checks presence across 5+ social networks/repositories and extracts public profile info.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
import concurrent.futures

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}


def check_github(username: str) -> tuple:
    """Check GitHub presence and fetch activity/profile data via API."""
    url = f"https://api.github.com/users/{username}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            updated_at = data.get('updated_at')
            activity = None
            if updated_at:
                try:
                    dt = datetime.strptime(updated_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                    days_ago = (datetime.now(timezone.utc) - dt).days
                    if days_ago <= 0:
                        activity = "Active on GitHub, last post 0 days ago"
                    else:
                        activity = f"Active on GitHub, last post {days_ago} days ago"
                except Exception:
                    activity = "Active on GitHub"
            return ("GitHub", "Found", activity)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ("GitHub", "Not Found", None)
        return ("GitHub", "Not Found", None)
    except Exception:
        return ("GitHub", "Not Found", None)


def check_facebook(username: str) -> tuple:
    """Check Facebook presence."""
    url = f"https://www.facebook.com/{username}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            if "Page Not Found" in content or "content is not available" in content.lower():
                return ("Facebook", "Not Found", None)
            return ("Facebook", "Found", None)
    except Exception:
        return ("Facebook", "Not Found", None)


def check_twitter(username: str) -> tuple:
    """Check Twitter / X presence."""
    url = f"https://x.com/{username}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return ("Twitter", "Found" if resp.status == 200 else "Not Found", None)
    except urllib.error.HTTPError:
        return ("Twitter", "Not Found", None)
    except Exception:
        return ("Twitter", "Not Found", None)


def check_linkedin(username: str) -> tuple:
    """Check LinkedIn presence."""
    url = f"https://www.linkedin.com/in/{username}"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            if "page-not-found" in content or "Profile Not Found" in content:
                return ("LinkedIn", "Not Found", None)
            return ("LinkedIn", "Found", None)
    except Exception:
        return ("LinkedIn", "Not Found", None)


def check_instagram(username: str) -> tuple:
    """Check Instagram presence."""
    url = f"https://www.instagram.com/{username}/"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            if "Page Not Found" in content or "Sorry, this page isn't available." in content:
                return ("Instagram", "Not Found", None)
            return ("Instagram", "Found", None)
    except Exception:
        return ("Instagram", "Not Found", None)


def search_by_username(username: str) -> str:
    """
    Performs OSINT username search across 5 key social networks and repositories.
    Returns formatted results including platform status and recent activity.
    """
    clean_user = username.strip().lstrip('@')
    if not clean_user:
        return "Error: Invalid or empty username provided."

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(check_facebook, clean_user),
            executor.submit(check_twitter, clean_user),
            executor.submit(check_linkedin, clean_user),
            executor.submit(check_instagram, clean_user),
            executor.submit(check_github, clean_user),
        ]
        results = [f.result() for f in futures]

    output_lines = []
    recent_activity = None

    for platform, status, activity in results:
        output_lines.append(f"{platform}: {status}")
        if activity:
            recent_activity = activity

    if recent_activity:
        output_lines.append(f"Recent Activity: {recent_activity}")

    return "\n".join(output_lines)
