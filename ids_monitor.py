#!/usr/bin/env python3
"""
Real-Time Intrusion Detection System (IDS)
Monitors network traffic and alerts on potential security threats
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
import json
import sqlite3
import logging
from collections import defaultdict
import threading
import time
import smtplib
from email.mime.text import MIMEText

class IntrusionDetector:
    def __init__(self, interface="eth0", db_path="ids_alerts.db"):
        self.interface = interface
        self.db_path = db_path
        self.setup_logging()
        self.setup_database()
        
        # Threat detection thresholds
        self.port_scan_threshold = 20  # ports scanned in time window
        self.syn_flood_threshold = 100  # SYN packets per IP in time window
        self.time_window = 60  # seconds
        
        # Tracking dictionaries
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.syn_flood_tracker = defaultdict(list)
        self.failed_login_tracker = defaultdict(list)
        
        # Threat signatures
        self.malicious_patterns = [
            b"../../etc/passwd",  # Path traversal
            b"union select",      # SQL injection
            b"<script>",          # XSS
            b"/bin/sh",           # Shell injection
            b"cmd.exe",           # Command injection
        ]
        
        # Known malicious IPs (you can integrate with threat feeds)
        self.blacklist = set()
        
        self.stats = {
            "packets_analyzed": 0,
            "alerts_generated": 0,
            "threats_detected": 0
        }
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_database(self):
        """Initialize SQLite database for alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                severity TEXT,
                alert_type TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                description TEXT,
                raw_data TEXT
            )
        ''')
        conn.commit()
        conn.close()
        
    def log_alert(self, severity, alert_type, src_ip, dst_ip, src_port, 
                  dst_port, protocol, description, raw_data=""):
        """Log security alert to database and file"""
        timestamp = datetime.now().isoformat()
        
        # Log to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, severity, alert_type, source_ip, 
                              dest_ip, source_port, dest_port, protocol, 
                              description, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, severity, alert_type, src_ip, dst_ip, src_port, 
              dst_port, protocol, description, raw_data))
        conn.commit()
        conn.close()
        
        # Log to file
        alert_msg = f"[{severity}] {alert_type}: {description} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        self.logger.warning(alert_msg)
        
        self.stats["alerts_generated"] += 1
        
        # Send notification for critical alerts
        if severity == "CRITICAL":
            self.send_notification(alert_msg)
            
    def send_notification(self, message):
        """Send alert notification (console for now, can integrate email/SMS)"""
        print(f"\n{'='*80}")
        print(f"🚨 CRITICAL ALERT 🚨")
        print(f"{message}")
        print(f"{'='*80}\n")
        
    def detect_port_scan(self, packet):
        """Detect port scanning attempts"""
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            current_time = time.time()
            
            # Track ports accessed by this source IP
            self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
            
            # Check if threshold exceeded
            if len(self.port_scan_tracker[src_ip][dst_ip]) >= self.port_scan_threshold:
                self.log_alert(
                    "HIGH",
                    "PORT_SCAN",
                    src_ip,
                    dst_ip,
                    packet[TCP].sport,
                    dst_port,
                    "TCP",
                    f"Port scan detected: {len(self.port_scan_tracker[src_ip][dst_ip])} ports scanned"
                )
                # Reset tracker after alert
                self.port_scan_tracker[src_ip][dst_ip].clear()
                self.stats["threats_detected"] += 1
                
    def detect_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            src_ip = packet[IP].src
            current_time = time.time()
            
            # Add to tracker
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Remove old entries outside time window
            self.syn_flood_tracker[src_ip] = [
                t for t in self.syn_flood_tracker[src_ip] 
                if current_time - t < self.time_window
            ]
            
            # Check threshold
            if len(self.syn_flood_tracker[src_ip]) >= self.syn_flood_threshold:
                self.log_alert(
                    "CRITICAL",
                    "SYN_FLOOD",
                    src_ip,
                    packet[IP].dst,
                    packet[TCP].sport,
                    packet[TCP].dport,
                    "TCP",
                    f"SYN flood attack detected: {len(self.syn_flood_tracker[src_ip])} SYN packets in {self.time_window}s"
                )
                self.syn_flood_tracker[src_ip].clear()
                self.stats["threats_detected"] += 1
                
    def detect_payload_threats(self, packet):
        """Detect malicious patterns in packet payload"""
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            
            for pattern in self.malicious_patterns:
                if pattern in payload.lower():
                    severity = "CRITICAL" if pattern in [b"/bin/sh", b"cmd.exe"] else "HIGH"
                    self.log_alert(
                        severity,
                        "MALICIOUS_PAYLOAD",
                        packet[IP].src if packet.haslayer(IP) else "N/A",
                        packet[IP].dst if packet.haslayer(IP) else "N/A",
                        packet[TCP].sport if packet.haslayer(TCP) else 0,
                        packet[TCP].dport if packet.haslayer(TCP) else 0,
                        "TCP" if packet.haslayer(TCP) else "UDP",
                        f"Malicious pattern detected: {pattern.decode('utf-8', errors='ignore')}",
                        payload[:200].hex()
                    )
                    self.stats["threats_detected"] += 1
                    
    def detect_blacklisted_ip(self, packet):
        """Check if packet is from blacklisted IP"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in self.blacklist:
                self.log_alert(
                    "CRITICAL",
                    "BLACKLISTED_IP",
                    src_ip,
                    packet[IP].dst,
                    packet[TCP].sport if packet.haslayer(TCP) else 0,
                    packet[TCP].dport if packet.haslayer(TCP) else 0,
                    "IP",
                    f"Traffic from blacklisted IP: {src_ip}"
                )
                self.stats["threats_detected"] += 1
                
    def detect_icmp_flood(self, packet):
        """Detect ICMP flood attacks"""
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            # Simple ICMP flood detection based on rate
            # In production, implement more sophisticated logic
            
    def analyze_packet(self, packet):
        """Main packet analysis function"""
        self.stats["packets_analyzed"] += 1
        
        if not packet.haslayer(IP):
            return
            
        try:
            # Run all detection modules
            self.detect_port_scan(packet)
            self.detect_syn_flood(packet)
            self.detect_payload_threats(packet)
            self.detect_blacklisted_ip(packet)
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            
    def cleanup_old_data(self):
        """Periodic cleanup of tracking data"""
        while True:
            time.sleep(300)  # Run every 5 minutes
            current_time = time.time()
            
            # Cleanup port scan tracker
            for src_ip in list(self.port_scan_tracker.keys()):
                if not self.port_scan_tracker[src_ip]:
                    del self.port_scan_tracker[src_ip]
                    
    def print_stats(self):
        """Print monitoring statistics"""
        while True:
            time.sleep(30)  # Print every 30 seconds
            print(f"\n--- IDS Statistics ---")
            print(f"Packets Analyzed: {self.stats['packets_analyzed']}")
            print(f"Alerts Generated: {self.stats['alerts_generated']}")
            print(f"Threats Detected: {self.stats['threats_detected']}")
            print(f"--------------------\n")
            
    def start(self):
        """Start the IDS"""
        self.logger.info(f"Starting IDS on interface {self.interface}")
        
        # Start background threads
        cleanup_thread = threading.Thread(target=self.cleanup_old_data, daemon=True)
        cleanup_thread.start()
        
        stats_thread = threading.Thread(target=self.print_stats, daemon=True)
        stats_thread.start()
        
        # Start packet sniffing
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                store=False  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            self.logger.info("IDS stopped by user")
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")

def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║   Real-Time Intrusion Detection System   ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Note: May need to run with sudo for packet capture
    # For testing without root: use 'any' interface or set up proper permissions
    
    ids = IntrusionDetector(interface="lo0")  # Change to your interface
    ids.start()

if __name__ == "__main__":
    main()