#!/usr/bin/env python3
"""
lucos_firewall - Host firewall manager for the lucOS estate.

Fetches public_ports configuration from lucos_configy and applies an
iptables/ip6tables ruleset: default DROP on inbound, with explicit ACCEPT
rules for declared ports + host SSH + ICMP + connection tracking.

See ADR-0007: https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md
Implementation tracked in: https://github.com/lucas42/lucos_firewall/issues/1
"""

import sys

def main():
    print("lucos_firewall: placeholder — implementation pending (see issue #1)", flush=True)
    sys.exit(1)

if __name__ == "__main__":
    main()
