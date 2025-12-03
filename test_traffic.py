#!/usr/bin/env python3
"""
IDS Test Traffic Generator
Generate various types of network traffic to test the IDS
"""

import socket
import time
import random
import argparse
from scapy.all import *
import sys
import os

class TrafficGenerator:
    def __init__(self, target_ip='127.0.0.1'):
        self.target_ip = target_ip
        
    def generate_port_scan(self, start_port=1, end_port=100):
        """Generate port scan traffic"""
        print(f"\n[*] Generating port scan: {self.target_ip}:{start_port}-{end_port}")
        
        for port in range(start_port, end_port + 1):
            try:
                # Send SYN packet
                ip = IP(dst=self.target_ip)
                syn = TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
                send(ip/syn, verbose=0)
                
                if port % 10 == 0:
                    print(f"  Scanning port {port}...")
                    
            except Exception as e:
                print(f"  Error scanning port {port}: {e}")
                
        print(f"[+] Port scan complete!\n")
        
    def generate_syn_flood(self, target_port=80, count=100, delay=0.01):
        """Generate SYN flood attack"""
        print(f"\n[*] Generating SYN flood to {self.target_ip}:{target_port}")
        print(f"    Packets: {count}, Delay: {delay}s")
        
        for i in range(count):
            try:
                # Random source port and IP
                src_port = random.randint(1024, 65535)
                
                ip = IP(dst=self.target_ip)
                syn = TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(0, 4294967295))
                send(ip/syn, verbose=0)
                
                if (i + 1) % 20 == 0:
                    print(f"  Sent {i + 1}/{count} SYN packets...")
                    
                time.sleep(delay)
                
            except Exception as e:
                print(f"  Error: {e}")
                break
                
        print(f"[+] SYN flood complete!\n")
        
    def generate_malicious_http(self, target_port=80):
        """Generate HTTP requests with malicious payloads"""
        print(f"\n[*] Generating malicious HTTP requests to {self.target_ip}:{target_port}")
        
        payloads = [
            "' OR '1'='1",                          # SQL injection
            "'; DROP TABLE users--",                # SQL injection
            "<script>alert('XSS')</script>",        # XSS
            "<img src=x onerror=alert('XSS')>",    # XSS
            "../../etc/passwd",                     # Path traversal
            "/bin/sh -c whoami",                    # Command injection
            "cmd.exe /c dir",                       # Command injection
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                # Create HTTP GET request with payload
                request = f"GET /search?q={payload} HTTP/1.1\r\n"
                request += f"Host: {self.target_ip}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                # Send via TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_ip, target_port))
                sock.send(request.encode())
                sock.close()
                
                print(f"  [{i}/{len(payloads)}] Sent: {payload[:50]}...")
                time.sleep(0.5)
                
            except Exception as e:
                print(f"  Error with payload '{payload}': {e}")
                
        print(f"[+] Malicious HTTP requests complete!\n")
        
    def generate_icmp_flood(self, count=50, delay=0.05):
        """Generate ICMP flood"""
        print(f"\n[*] Generating ICMP flood to {self.target_ip}")
        print(f"    Packets: {count}, Delay: {delay}s")
        
        for i in range(count):
            try:
                # Send ICMP echo request
                ip = IP(dst=self.target_ip)
                icmp = ICMP(type=8)  # Echo request
                payload = Raw(load=b'X' * 56)
                send(ip/icmp/payload, verbose=0)
                
                if (i + 1) % 10 == 0:
                    print(f"  Sent {i + 1}/{count} ICMP packets...")
                    
                time.sleep(delay)
                
            except Exception as e:
                print(f"  Error: {e}")
                break
                
        print(f"[+] ICMP flood complete!\n")
        
    def generate_normal_traffic(self, count=20):
        """Generate normal-looking traffic"""
        print(f"\n[*] Generating normal traffic")
        
        normal_ports = [80, 443, 53, 22]
        
        for i in range(count):
            try:
                port = random.choice(normal_ports)
                
                # Send SYN packet
                ip = IP(dst=self.target_ip)
                syn = TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
                send(ip/syn, verbose=0)
                
                if (i + 1) % 5 == 0:
                    print(f"  Sent {i + 1}/{count} normal packets...")
                    
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                print(f"  Error: {e}")
                
        print(f"[+] Normal traffic complete!\n")
        
    def run_comprehensive_test(self):
        """Run all tests in sequence"""
        print("\n" + "="*60)
        print("IDS COMPREHENSIVE TEST")
        print("="*60)
        print(f"\nTarget: {self.target_ip}")
        print("\nThis will generate various attack patterns to test the IDS.")
        print("Make sure the IDS is running before starting!\n")
        
        input("Press Enter to continue...")
        
        # Test 1: Normal traffic
        print("\n[TEST 1] Generating normal traffic...")
        self.generate_normal_traffic(10)
        time.sleep(2)
        
        # Test 2: Port scan
        print("\n[TEST 2] Generating port scan...")
        self.generate_port_scan(1, 50)
        time.sleep(2)
        
        # Test 3: SYN flood
        print("\n[TEST 3] Generating SYN flood...")
        self.generate_syn_flood(80, 50, 0.02)
        time.sleep(2)
        
        # Test 4: Malicious HTTP
        print("\n[TEST 4] Generating malicious HTTP requests...")
        try:
            self.generate_malicious_http(80)
        except:
            print("  [!] HTTP test skipped (no web server running)")
        time.sleep(2)
        
        # Test 5: ICMP flood
        print("\n[TEST 5] Generating ICMP flood...")
        self.generate_icmp_flood(30, 0.1)
        
        print("\n" + "="*60)
        print("TESTING COMPLETE")
        print("="*60)
        print("\nCheck the IDS output and database for detected alerts.")
        print("Run: python3 view_alerts.py --recent 20\n")

def main():
    parser = argparse.ArgumentParser(description='IDS Test Traffic Generator')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--port-scan', action='store_true', help='Generate port scan')
    parser.add_argument('--syn-flood', action='store_true', help='Generate SYN flood')
    parser.add_argument('--malicious-http', action='store_true', help='Generate malicious HTTP')
    parser.add_argument('--icmp-flood', action='store_true', help='Generate ICMP flood')
    parser.add_argument('--normal', action='store_true', help='Generate normal traffic')
    parser.add_argument('--all', action='store_true', help='Run comprehensive test')
    
    args = parser.parse_args()
    
    # Check if running as root (needed for Scapy)
    if os.geteuid() != 0:
        print("Error: This script must be run as root (use sudo)")
        sys.exit(1)
        
    generator = TrafficGenerator(args.target)
    
    if args.port_scan:
        generator.generate_port_scan()
    elif args.syn_flood:
        generator.generate_syn_flood()
    elif args.malicious_http:
        generator.generate_malicious_http()
    elif args.icmp_flood:
        generator.generate_icmp_flood()
    elif args.normal:
        generator.generate_normal_traffic()
    elif args.all:
        generator.run_comprehensive_test()
    else:
        print("No test selected. Use --help for options.")
        print("\nQuick start: sudo python3 test_traffic.py --all")

if __name__ == '__main__':
    main()