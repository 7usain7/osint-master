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

import argparse
import sys

from modules.name_search import search_by_name
from modules.ip_search import search_by_ip
from modules.username_search import search_by_username
from modules.domain_search import search_by_domain
from modules.output_manager import save_output

def main():
    parser = argparse.ArgumentParser(
        description="Welcome to osintmaster multi-function Tool",
        add_help=True
    )
    
    parser.add_argument("-n", "--name", metavar='"Full Name"', help="Search information by full name")
    parser.add_argument("-i", "--ip", metavar='"IP Address"', help="Search information by IP address")
    parser.add_argument("-u", "--username", metavar='"Username"', help="Search information by username")
    parser.add_argument("-d", "--domain", metavar='"Domain"', help="Enumerate subdomains and check for takeover risks")
    parser.add_argument("-o", "--output", metavar='"FileName"', help="File name to save output")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not (args.name or args.ip or args.username or args.domain):
        print("Error: Please specify at least one search option (-n, -i, -u, or -d).")
        parser.print_help()
        sys.exit(1)

    results = []


    if args.name:
        res = search_by_name(args.name)
        if res:
            results.append(res)
            
    if args.ip:
        res = search_by_ip(args.ip)
        if res:
            results.append(res)

    if args.username:
        res = search_by_username(args.username)
        if res:
            results.append(res)

    if args.domain:
        res = search_by_domain(args.domain)
        if res:
            results.append(res)

    if results:
        formatted_data = "\n\n".join(results)
        save_output(formatted_data, args.output)

if __name__ == "__main__":
    main()
