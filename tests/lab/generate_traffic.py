#!/usr/bin/env python3
"""
Synthetic Traffic Generator for FALCON-X Testing
Safely generates test traffic for local/lab environments only
"""

import argparse
import logging
import sys
import ipaddress
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, send, sr1

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def is_safe_target(target: str) -> bool:
    """Check if target is safe (localhost or private IP)"""
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return target in ['localhost', '127.0.0.1']


def generate_normal_traffic(target: str, count: int = 10):
    """Generate normal-looking traffic"""
    logger.info(f"Generating {count} normal packets to {target}")

    for i in range(count):
        # Normal TCP packets
        packet = IP(dst=target)/TCP(dport=80, flags='S')
        send(packet, verbose=0)

        # Normal UDP packets
        packet = IP(dst=target)/UDP(dport=53)
        send(packet, verbose=0)

    logger.info(f"Generated {count * 2} normal packets")


def generate_icmp_burst(target: str, count: int = 30):
    """Generate ICMP burst"""
    logger.info(f"Generating {count} ICMP packets to {target}")

    for i in range(count):
        packet = IP(dst=target)/ICMP()
        send(packet, verbose=0)

    logger.info(f"Generated {count} ICMP packets")


def generate_dns_burst(target: str, count: int = 20):
    """Generate DNS burst"""
    logger.info(f"Generating {count} DNS packets to {target}")

    for i in range(count):
        packet = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"test{i}.example.com"))
        send(packet, verbose=0)

    logger.info(f"Generated {count} DNS packets")


def generate_syn_burst(target: str, count: int = 50):
    """Generate SYN burst"""
    logger.info(f"Generating {count} SYN packets to {target}")

    for i in range(count):
        packet = IP(dst=target)/TCP(dport=80, flags='S')
        send(packet, verbose=0)

    logger.info(f"Generated {count} SYN packets")


def generate_port_scan_simulation(target: str, ports: int = 15):
    """Simulate port scan behavior"""
    logger.info(f"Simulating port scan to {target} on {ports} ports")

    for port in range(1, ports + 1):
        packet = IP(dst=target)/TCP(dport=port, flags='S')
        send(packet, verbose=0)

    logger.info(f"Generated {ports} SYN packets to different ports")


def main():
    parser = argparse.ArgumentParser(description='FALCON-X Synthetic Traffic Generator')
    parser.add_argument('--target', required=True, help='Target IP address (must be localhost or private IP)')
    parser.add_argument('--mode', default='normal', choices=['normal', 'icmp-burst', 'dns-burst', 'syn-burst', 'port-scan-simulation'],
                       help='Traffic generation mode')
    parser.add_argument('--count', type=int, default=10, help='Number of packets/bursts')
    parser.add_argument('--ports', type=int, default=15, help='Number of ports for port scan simulation')

    args = parser.parse_args()

    # Safety check
    if not is_safe_target(args.target):
        logger.error(f"Unsafe target: {args.target}. Only localhost and private IPs are allowed.")
        sys.exit(1)

    logger.info(f"Target: {args.target}, Mode: {args.mode}")

    try:
        if args.mode == 'normal':
            generate_normal_traffic(args.target, args.count)
        elif args.mode == 'icmp-burst':
            generate_icmp_burst(args.target, args.count)
        elif args.mode == 'dns-burst':
            generate_dns_burst(args.target, args.count)
        elif args.mode == 'syn-burst':
            generate_syn_burst(args.target, args.count)
        elif args.mode == 'port-scan-simulation':
            generate_port_scan_simulation(args.target, args.ports)

        logger.info("Traffic generation complete")

    except Exception as e:
        logger.error(f"Error generating traffic: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
