#!/usr/bin/env python3
"""
🔍 Network Scanner - Security Automation Tool

A comprehensive network scanning utility for ethical hackers and security professionals.
Scans networks to discover hosts, open ports, and services.

Author: Rohith D
CEH Student | Aspiring Cybersecurity Professional
https://github.com/ROHITHD300900
"""

import socket
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Terminal colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Common ports to scan
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Proxy'
}

def banner():
    """Display the tool banner"""
    print(f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════════╗
║  🔍 Network Scanner - Security Automation Tool                 ║
║  Version: 1.0.0 | Author: Rohith D                             ║
║  For Educational Purposes Only                                 ║
╚═══════════════════════════════════════════════════════════════╝{Colors.END}
    """)

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scan a single port on the target host.
    
    Args:
        host: Target IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary with port status and service info
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            return {
                'port': port,
                'status': 'open',
                'service': service
            }
    except socket.error:
        pass
    
    return {'port': port, 'status': 'closed', 'service': None}

def scan_host(host: str, ports: list = None, threads: int = 50) -> dict:
    """
    Scan multiple ports on a host using threading.
    
    Args:
        host: Target IP or hostname
        ports: List of ports to scan (default: common ports)
        threads: Number of concurrent threads
    
    Returns:
        Dictionary with scan results
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    results = {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'open_ports': [],
        'closed_ports': 0
    }
    
    print(f"\n{Colors.YELLOW}[*] Scanning {host}...{Colors.END}")
    print(f"{Colors.YELLOW}[*] Ports to scan: {len(ports)}{Colors.END}\n")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result['status'] == 'open':
                results['open_ports'].append(result)
                print(f"{Colors.GREEN}[+] Port {result['port']}/tcp OPEN - {result['service']}{Colors.END}")
            else:
                results['closed_ports'] += 1
    
    return results

def print_summary(results: dict):
    """Print scan summary"""
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*60}{Colors.END}")
    print(f"  Host: {results['host']}")
    print(f"  Scan Time: {results['scan_time']}")
    print(f"  Open Ports: {len(results['open_ports'])}")
    print(f"  Closed Ports: {results['closed_ports']}")
    
    if results['open_ports']:
        print(f"\n{Colors.GREEN}  Open Ports:{Colors.END}")
        for port_info in results['open_ports']:
            print(f"    - {port_info['port']}/tcp ({port_info['service']})")
    
    print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Network Scanner - Discover hosts and open ports'
    )
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP address or hostname'
    )
    parser.add_argument(
        '-p', '--ports',
        default=None,
        help='Ports to scan (e.g., 22,80,443 or 1-1000)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for JSON results'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of threads (default: 50)'
    )
    
    args = parser.parse_args()
    
    banner()
    
    # Parse ports if provided
    ports = None
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
    
    # Run the scan
    results = scan_host(args.target, ports, args.threads)
    
    # Print summary
    print_summary(results)
    
    # Save to file if specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Colors.GREEN}[+] Results saved to {args.output}{Colors.END}")

if __name__ == '__main__':
    main()
