#!/usr/bin/env python3
"""
OSINT-Master CLI Tool
=====================
A multi-functional passive reconnaissance tool.

Usage:
    osintmaster -n "Full Name" [-o filename]
    osintmaster -i "IP Address" [-o filename]
    osintmaster -u "Username" [-o filename]
    osintmaster -d "Domain" [-o filename]
"""

import sys
import argparse

from modules.name_search import search_by_name
from modules.ip_search import search_by_ip
from modules.username_search import search_by_username
from modules.domain_search import search_by_domain
from modules.output_manager import save_output

def main():
    pass

if __name__ == "__main__":
    main()
