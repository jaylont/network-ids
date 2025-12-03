# Network Intrusion Detection System

Real-time network IDS with ML-based anomaly detection built in Python.

## Features
- Real-time packet analysis
- Port scan detection
- SYN flood detection  
- Malicious payload inspection
- ML anomaly detection
- Live dashboard
- SQLite logging

## Quick Start
```bash
# Install dependencies
pip install scapy scikit-learn numpy joblib

# Run IDS
sudo python3 ids_monitor.py

# View dashboard (new terminal)
python3 dashboard.py

# Test it (new terminal)  
sudo python3 test_traffic.py --all
```

## Files
- `ids_monitor.py` - Main IDS engine
- `ml_anomaly_detector.py` - ML module
- `view_alerts.py` - Alert viewer
- `dashboard.py` - Live dashboard
- `test_traffic.py` - Traffic generator

## Author
Jaylon Taylor

Built as part of cybersecurity portfolio.
