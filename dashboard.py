#!/usr/bin/env python3
"""
IDS Live Dashboard
Real-time display of IDS statistics and alerts
"""

import sqlite3
import time
import os
from datetime import datetime, timedelta
from collections import Counter

class IDSDashboard:
    def __init__(self, db_path='ids_alerts.db', refresh_interval=5):
        self.db_path = db_path
        self.refresh_interval = refresh_interval
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
        
    def get_stats(self):
        """Get current statistics from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total alerts
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0]
            
            # Alerts by severity
            cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM alerts 
                GROUP BY severity
            ''')
            severity_counts = dict(cursor.fetchall())
            
            # Alerts in last hour
            last_hour = (datetime.now() - timedelta(hours=1)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp >= ?', (last_hour,))
            alerts_last_hour = cursor.fetchone()[0]
            
            # Alerts in last 24 hours
            last_day = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp >= ?', (last_day,))
            alerts_last_day = cursor.fetchone()[0]
            
            # Top alert types
            cursor.execute('''
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
                LIMIT 5
            ''')
            top_types = cursor.fetchall()
            
            # Top source IPs
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 5
            ''', (last_day,))
            top_sources = cursor.fetchall()
            
            # Recent alerts
            cursor.execute('''
                SELECT timestamp, severity, alert_type, source_ip, dest_ip
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 5
            ''')
            recent_alerts = cursor.fetchall()
            
            conn.close()
            
            return {
                'total_alerts': total_alerts,
                'severity_counts': severity_counts,
                'alerts_last_hour': alerts_last_hour,
                'alerts_last_day': alerts_last_day,
                'top_types': top_types,
                'top_sources': top_sources,
                'recent_alerts': recent_alerts
            }
            
        except sqlite3.Error as e:
            return None
            
    def draw_bar(self, value, max_value, width=30):
        """Draw a simple bar chart"""
        if max_value == 0:
            return ''
        filled = int((value / max_value) * width)
        return '█' * filled + '░' * (width - filled)
        
    def display_dashboard(self, stats):
        """Display the dashboard"""
        self.clear_screen()
        
        # Header
        print("╔" + "═" * 78 + "╗")
        print("║" + " IDS LIVE DASHBOARD ".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        print()
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Last Update: {current_time}".center(80))
        print()
        
        # Overall Statistics
        print("┌─ OVERALL STATISTICS " + "─" * 57 + "┐")
        print(f"│ Total Alerts:        {stats['total_alerts']:>6}                                           │")
        print(f"│ Alerts (Last Hour):  {stats['alerts_last_hour']:>6}                                           │")
        print(f"│ Alerts (Last 24h):   {stats['alerts_last_day']:>6}                                           │")
        print("└" + "─" * 78 + "┘")
        print()
        
        # Severity Distribution
        print("┌─ ALERTS BY SEVERITY " + "─" * 57 + "┐")
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severity_colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'LOW': '\033[92m'
        }
        reset = '\033[0m'
        
        max_count = max(stats['severity_counts'].values()) if stats['severity_counts'] else 1
        
        for severity in severity_order:
            count = stats['severity_counts'].get(severity, 0)
            bar = self.draw_bar(count, max_count, 30)
            color = severity_colors.get(severity, '')
            print(f"│ {color}{severity:10}{reset} {count:5} {bar:<30} │")
            
        print("└" + "─" * 78 + "┘")
        print()
        
        # Top Alert Types
        print("┌─ TOP ALERT TYPES " + "─" * 60 + "┐")
        
        if stats['top_types']:
            max_count = stats['top_types'][0][1] if stats['top_types'] else 1
            for alert_type, count in stats['top_types']:
                bar = self.draw_bar(count, max_count, 25)
                print(f"│ {alert_type:25} {count:5} {bar:<25} │")
        else:
            print("│ " + "No alerts yet".center(76) + " │")
            
        print("└" + "─" * 78 + "┘")
        print()
        
        # Top Source IPs (Last 24h)
        print("┌─ TOP SOURCE IPs (24h) " + "─" * 54 + "┐")
        
        if stats['top_sources']:
            max_count = stats['top_sources'][0][1] if stats['top_sources'] else 1
            for ip, count in stats['top_sources']:
                bar = self.draw_bar(count, max_count, 25)
                print(f"│ {ip:20} {count:5} {bar:<25}    │")
        else:
            print("│ " + "No alerts in last 24 hours".center(76) + " │")
            
        print("└" + "─" * 78 + "┘")
        print()
        
        # Recent Alerts
        print("┌─ RECENT ALERTS " + "─" * 62 + "┐")
        
        if stats['recent_alerts']:
            for timestamp, severity, alert_type, src_ip, dst_ip in stats['recent_alerts']:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%H:%M:%S")
                color = severity_colors.get(severity, '')
                
                # Truncate if needed
                alert_type_short = alert_type[:15]
                src_short = src_ip[:15]
                dst_short = dst_ip[:15]
                
                print(f"│ {time_str} {color}[{severity:8}]{reset} {alert_type_short:15} {src_short:15} → {dst_short:15} │")
        else:
            print("│ " + "No alerts yet".center(76) + " │")
            
        print("└" + "─" * 78 + "┘")
        print()
        
        # Footer
        print(f"Refreshing every {self.refresh_interval}s... (Press Ctrl+C to exit)".center(80))
        
    def run(self):
        """Run the dashboard"""
        print("\nStarting IDS Dashboard...")
        print(f"Database: {self.db_path}")
        print(f"Refresh: {self.refresh_interval}s\n")
        
        try:
            while True:
                stats = self.get_stats()
                
                if stats is None:
                    self.clear_screen()
                    print("\n" + "="*80)
                    print("ERROR: Cannot connect to database")
                    print(f"Database file: {self.db_path}")
                    print("Make sure the IDS is running and creating the database.")
                    print("="*80 + "\n")
                    time.sleep(self.refresh_interval)
                    continue
                    
                self.display_dashboard(stats)
                time.sleep(self.refresh_interval)
                
        except KeyboardInterrupt:
            print("\n\nDashboard stopped.\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='IDS Live Dashboard')
    parser.add_argument('--db', default='ids_alerts.db', help='Database file path')
    parser.add_argument('--refresh', type=int, default=5, help='Refresh interval in seconds')
    
    args = parser.parse_args()
    
    dashboard = IDSDashboard(args.db, args.refresh)
    dashboard.run()

if __name__ == '__main__':
    main()