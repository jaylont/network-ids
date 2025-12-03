#!/usr/bin/env python3
"""
IDS Alert Viewer and Analyzer
View and analyze alerts from the IDS database
"""

import sqlite3
import argparse
from datetime import datetime, timedelta
from collections import Counter
import sys

class AlertViewer:
    def __init__(self, db_path='ids_alerts.db'):
        self.db_path = db_path
        
    def connect(self):
        """Connect to alerts database"""
        try:
            return sqlite3.connect(self.db_path)
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")
            sys.exit(1)
            
    def view_recent_alerts(self, limit=10):
        """View most recent alerts"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, severity, alert_type, source_ip, dest_ip, 
                   source_port, dest_port, description
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        print(f"\n{'='*80}")
        print(f"RECENT ALERTS (Last {limit})")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print("No alerts found.")
            conn.close()
            return
            
        for row in results:
            timestamp, severity, alert_type, src_ip, dst_ip, src_port, dst_port, desc = row
            
            # Color code by severity
            if severity == 'CRITICAL':
                color = '\033[91m'  # Red
            elif severity == 'HIGH':
                color = '\033[93m'  # Yellow
            elif severity == 'MEDIUM':
                color = '\033[94m'  # Blue
            else:
                color = '\033[92m'  # Green
            reset = '\033[0m'
            
            print(f"{timestamp}")
            print(f"{color}[{severity}] {alert_type}{reset}")
            print(f"Source: {src_ip}:{src_port} → Destination: {dst_ip}:{dst_port}")
            print(f"Description: {desc}")
            print(f"{'-'*80}\n")
            
        conn.close()
        
    def view_alerts_by_type(self):
        """View alert statistics by type"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            GROUP BY alert_type
            ORDER BY count DESC
        ''')
        
        print(f"\n{'='*80}")
        print("ALERTS BY TYPE")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print("No alerts found.")
            conn.close()
            return
            
        total = sum(count for _, count in results)
        
        for alert_type, count in results:
            percentage = (count / total) * 100
            bar_length = int(percentage / 2)
            bar = '█' * bar_length
            print(f"{alert_type:30} {count:5} {bar} {percentage:.1f}%")
            
        print(f"\nTotal Alerts: {total}\n")
        conn.close()
        
    def view_alerts_by_severity(self):
        """View alert statistics by severity"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        ''')
        
        print(f"\n{'='*80}")
        print("ALERTS BY SEVERITY")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print("No alerts found.")
            conn.close()
            return
            
        total = sum(count for _, count in results)
        
        severity_colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'LOW': '\033[92m'
        }
        reset = '\033[0m'
        
        for severity, count in results:
            percentage = (count / total) * 100
            bar_length = int(percentage / 2)
            bar = '█' * bar_length
            color = severity_colors.get(severity, '')
            print(f"{color}{severity:15}{reset} {count:5} {bar} {percentage:.1f}%")
            
        print(f"\nTotal Alerts: {total}\n")
        conn.close()
        
    def view_top_attackers(self, limit=10):
        """View top source IPs generating alerts"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM alerts
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        
        print(f"\n{'='*80}")
        print(f"TOP {limit} SOURCE IPs")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print("No alerts found.")
            conn.close()
            return
            
        total = sum(count for _, count in results)
        
        for i, (ip, count) in enumerate(results, 1):
            percentage = (count / total) * 100
            bar_length = int(percentage / 2)
            bar = '█' * bar_length
            print(f"{i:2}. {ip:20} {count:5} {bar} {percentage:.1f}%")
            
        print()
        conn.close()
        
    def view_timeline(self, hours=24):
        """View alert timeline for last N hours"""
        conn = self.connect()
        cursor = conn.cursor()
        
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
            SELECT timestamp, severity, alert_type
            FROM alerts
            WHERE timestamp >= ?
            ORDER BY timestamp ASC
        ''', (since,))
        
        print(f"\n{'='*80}")
        print(f"ALERT TIMELINE (Last {hours} hours)")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print(f"No alerts in the last {hours} hours.")
            conn.close()
            return
            
        # Group by hour
        hourly_counts = Counter()
        for timestamp, _, _ in results:
            dt = datetime.fromisoformat(timestamp)
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] += 1
            
        # Display timeline
        max_count = max(hourly_counts.values())
        for hour in sorted(hourly_counts.keys()):
            count = hourly_counts[hour]
            bar_length = int((count / max_count) * 50)
            bar = '█' * bar_length
            print(f"{hour} {count:4} {bar}")
            
        print(f"\nTotal Alerts: {len(results)}\n")
        conn.close()
        
    def search_alerts(self, search_term):
        """Search alerts by IP or description"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, severity, alert_type, source_ip, dest_ip, description
            FROM alerts
            WHERE source_ip LIKE ? OR dest_ip LIKE ? OR description LIKE ?
            ORDER BY timestamp DESC
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        
        print(f"\n{'='*80}")
        print(f"SEARCH RESULTS: '{search_term}'")
        print(f"{'='*80}\n")
        
        results = cursor.fetchall()
        if not results:
            print("No matching alerts found.")
            conn.close()
            return
            
        for row in results:
            timestamp, severity, alert_type, src_ip, dst_ip, desc = row
            print(f"{timestamp}")
            print(f"[{severity}] {alert_type}")
            print(f"{src_ip} → {dst_ip}")
            print(f"{desc}")
            print(f"{'-'*80}\n")
            
        print(f"Found {len(results)} matching alerts\n")
        conn.close()
        
    def export_to_csv(self, output_file='alerts_export.csv'):
        """Export alerts to CSV file"""
        import csv
        
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts')
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([desc[0] for desc in cursor.description])
            # Write data
            writer.writerows(cursor.fetchall())
            
        conn.close()
        print(f"\nAlerts exported to: {output_file}\n")
        
    def generate_report(self):
        """Generate comprehensive report"""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
        critical_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
        high_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT MIN(timestamp), MAX(timestamp) FROM alerts')
        first_alert, last_alert = cursor.fetchone()
        
        print(f"\n{'='*80}")
        print("IDS ALERT REPORT")
        print(f"{'='*80}\n")
        
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nAlert Period:")
        print(f"  First Alert: {first_alert or 'N/A'}")
        print(f"  Last Alert:  {last_alert or 'N/A'}")
        
        print(f"\nTotal Alerts: {total_alerts}")
        print(f"  Critical: {critical_count}")
        print(f"  High:     {high_count}")
        
        print(f"\n{'-'*80}\n")
        
        # Show top alert types
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            GROUP BY alert_type
            ORDER BY count DESC
            LIMIT 5
        ''')
        
        print("Top 5 Alert Types:")
        for alert_type, count in cursor.fetchall():
            print(f"  {alert_type:30} {count}")
            
        # Show top attackers
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM alerts
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 5
        ''')
        
        print("\nTop 5 Source IPs:")
        for ip, count in cursor.fetchall():
            print(f"  {ip:20} {count}")
            
        print(f"\n{'='*80}\n")
        conn.close()

def main():
    parser = argparse.ArgumentParser(description='IDS Alert Viewer')
    parser.add_argument('--db', default='ids_alerts.db', help='Database file path')
    parser.add_argument('--recent', type=int, metavar='N', help='Show N recent alerts')
    parser.add_argument('--by-type', action='store_true', help='Show alerts by type')
    parser.add_argument('--by-severity', action='store_true', help='Show alerts by severity')
    parser.add_argument('--top-attackers', type=int, metavar='N', help='Show top N attackers')
    parser.add_argument('--timeline', type=int, metavar='HOURS', help='Show timeline for last N hours')
    parser.add_argument('--search', type=str, metavar='TERM', help='Search alerts')
    parser.add_argument('--export', type=str, metavar='FILE', help='Export to CSV')
    parser.add_argument('--report', action='store_true', help='Generate comprehensive report')
    
    args = parser.parse_args()
    
    viewer = AlertViewer(args.db)
    
    if args.recent:
        viewer.view_recent_alerts(args.recent)
    elif args.by_type:
        viewer.view_alerts_by_type()
    elif args.by_severity:
        viewer.view_alerts_by_severity()
    elif args.top_attackers:
        viewer.view_top_attackers(args.top_attackers)
    elif args.timeline:
        viewer.view_timeline(args.timeline)
    elif args.search:
        viewer.search_alerts(args.search)
    elif args.export:
        viewer.export_to_csv(args.export)
    elif args.report:
        viewer.generate_report()
    else:
        # Default: show recent alerts
        viewer.view_recent_alerts(10)
        print("\nUse --help for more options\n")

if __name__ == '__main__':
    main()