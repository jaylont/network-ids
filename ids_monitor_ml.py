#!/usr/bin/env python3
"""
IDS with ML Anomaly Detection
Enhanced version of the original IDS
"""

# Import your original IDS
from ids_monitor import IntrusionDetector

# Import ML components (save the code above as ml_anomaly_detector.py)
from ml_anomaly_detector import MLAnomalyDetector, MLEnhancedIDS

def main():
    print("""
    ╔════════════════════════════════════════════╗
    ║   IDS with ML Anomaly Detection           ║
    ╚════════════════════════════════════════════╝
    """)
    
    # Create base IDS
    base_ids = IntrusionDetector(interface="lo0")
    
    # Create ML detector
    ml_detector = MLAnomalyDetector(model_path='ml_models/')
    
    # Create enhanced IDS
    enhanced_ids = MLEnhancedIDS(base_ids, ml_detector)
    
    # Check if we need to train
    if not ml_detector.is_trained:
        print("\n⚠️  ML model not trained yet!")
        print("Options:")
        print("  1. Enter training mode (observe normal traffic for 5 min)")
        print("  2. Skip ML detection for now")
        
        choice = input("\nEnter choice (1/2): ")
        
        if choice == "1":
            enhanced_ids.start_training_mode(duration_seconds=300)
    
    print("\n[*] Starting enhanced IDS with ML anomaly detection...")
    print("[*] Press Ctrl+C to stop\n")
    
    # Start monitoring with ML
    try:
        import scapy.all as scapy
        scapy.sniff(
            iface=base_ids.interface,
            prn=enhanced_ids.analyze_packet_with_ml,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] IDS stopped by user")

if __name__ == "__main__":
    main()