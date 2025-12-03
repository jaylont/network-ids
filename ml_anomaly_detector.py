#!/usr/bin/env python3
"""
ML Anomaly Detection Module for IDS
Uses Isolation Forest for detecting abnormal network behavior
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime
from collections import deque
import logging
import time

class MLAnomalyDetector:
    def __init__(self, model_path='ml_models/'):
        self.model_path = model_path
        
        # Logging FIRST
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Then other attributes
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.packet_history = deque(maxlen=1000)
        self.feature_history = []
        self.is_trained = False
        
        # Initialize models LAST
        self.setup_models()
        
    def setup_models(self):
        """Initialize ML models"""
        try:
            # Try to load existing model
            self.isolation_forest = joblib.load(f'{self.model_path}isolation_forest.pkl')
            self.scaler = joblib.load(f'{self.model_path}scaler.pkl')
            self.is_trained = True
            self.logger.info("Loaded existing ML models")
        except:
            # Create new model
            self.isolation_forest = IsolationForest(
                contamination=0.1,  # Expected % of anomalies
                n_estimators=100,
                max_samples='auto',
                random_state=42
            )
            self.logger.info("Created new ML models")
    
    def extract_features(self, packet):
        """
        Extract features from packet for ML analysis
        Returns a feature vector
        """
        features = []
        
        try:
            # Basic packet features
            features.append(len(packet) if packet else 0)  # Packet size
            
            # IP layer features
            if packet.haslayer('IP'):
                features.append(packet['IP'].ttl)  # Time to live
                features.append(packet['IP'].len)  # IP packet length
                features.append(1 if packet['IP'].flags.DF else 0)  # Don't Fragment flag
                features.append(1 if packet['IP'].flags.MF else 0)  # More Fragments flag
                
                # Convert IP to numeric
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                features.append(self._ip_to_int(src_ip))
                features.append(self._ip_to_int(dst_ip))
            else:
                features.extend([0, 0, 0, 0, 0, 0])
            
            # TCP layer features
            if packet.haslayer('TCP'):
                features.append(packet['TCP'].sport)  # Source port
                features.append(packet['TCP'].dport)  # Dest port
                features.append(packet['TCP'].window)  # Window size
                features.append(len(packet['TCP'].payload) if packet['TCP'].payload else 0)
                
                # TCP flags as binary features
                flags = packet['TCP'].flags
                features.append(1 if 'S' in str(flags) else 0)  # SYN
                features.append(1 if 'A' in str(flags) else 0)  # ACK
                features.append(1 if 'F' in str(flags) else 0)  # FIN
                features.append(1 if 'R' in str(flags) else 0)  # RST
                features.append(1 if 'P' in str(flags) else 0)  # PSH
                features.append(1 if 'U' in str(flags) else 0)  # URG
            else:
                features.extend([0] * 10)
            
            # UDP layer features
            if packet.haslayer('UDP'):
                features.append(packet['UDP'].sport)
                features.append(packet['UDP'].dport)
                features.append(len(packet['UDP'].payload) if packet['UDP'].payload else 0)
            else:
                features.extend([0, 0, 0])
            
            # ICMP layer features
            if packet.haslayer('ICMP'):
                features.append(packet['ICMP'].type)
                features.append(packet['ICMP'].code)
            else:
                features.extend([0, 0])
            
            # Protocol type
            if packet.haslayer('TCP'):
                features.append(6)  # TCP protocol number
            elif packet.haslayer('UDP'):
                features.append(17)  # UDP protocol number
            elif packet.haslayer('ICMP'):
                features.append(1)  # ICMP protocol number
            else:
                features.append(0)
            
            # Time-based features (from packet history)
            features.extend(self._get_temporal_features(packet))
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            # Return zero vector if error
            features = [0] * 30
        
        return np.array(features).reshape(1, -1)
    
    def _ip_to_int(self, ip_str):
        """Convert IP address to integer"""
        try:
            parts = ip_str.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                   (int(parts[2]) << 8) + int(parts[3])
        except:
            return 0
    
    def _get_temporal_features(self, packet):
        """Extract time-based features from packet history"""
        features = []
        
        # Add current packet to history
        current_time = datetime.now().timestamp()
        self.packet_history.append({
            'time': current_time,
            'packet': packet
        })
        
        # Calculate inter-arrival times
        if len(self.packet_history) > 1:
            recent_times = [p['time'] for p in list(self.packet_history)[-10:]]
            if len(recent_times) > 1:
                intervals = np.diff(recent_times)
                features.append(np.mean(intervals))  # Mean inter-arrival time
                features.append(np.std(intervals))   # Std of inter-arrival
                features.append(np.min(intervals))   # Min interval
                features.append(np.max(intervals))   # Max interval
            else:
                features.extend([0, 0, 0, 0])
        else:
            features.extend([0, 0, 0, 0])
        
        # Packet rate (packets per second in last 10 packets)
        if len(self.packet_history) > 1:
            time_window = current_time - self.packet_history[-min(10, len(self.packet_history))]['time']
            if time_window > 0:
                packet_rate = min(10, len(self.packet_history)) / time_window
                features.append(packet_rate)
            else:
                features.append(0)
        else:
            features.append(0)
        
        return features
    
    def train_on_normal_traffic(self, normal_packets, epochs=1):
        """
        Train the model on normal traffic
        Call this during a baseline period
        """
        self.logger.info(f"Training on {len(normal_packets)} normal packets...")
        
        # Extract features from all packets
        feature_vectors = []
        for packet in normal_packets:
            features = self.extract_features(packet)
            feature_vectors.append(features.flatten())
        
        X = np.array(feature_vectors)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        
        self.is_trained = True
        self.logger.info("Training complete!")
        
        # Save models
        self.save_models()
    
    def detect_anomaly(self, packet):
        """
        Detect if a packet is anomalous
        Returns: (is_anomaly, anomaly_score, features)
        """
        if not self.is_trained:
            return False, 0.0, None
        
        try:
            # Extract features
            features = self.extract_features(packet)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.isolation_forest.predict(features_scaled)[0]
            
            # Get anomaly score
            anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
            
            # -1 means anomaly, 1 means normal
            is_anomaly = (prediction == -1)
            
            # Convert score to 0-1 range (more negative = more anomalous)
            normalized_score = 1.0 / (1.0 + np.exp(anomaly_score))
            
            return is_anomaly, normalized_score, features.flatten()
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return False, 0.0, None
    
    def save_models(self):
        """Save trained models to disk"""
        import os
        os.makedirs(self.model_path, exist_ok=True)
        
        joblib.dump(self.isolation_forest, f'{self.model_path}isolation_forest.pkl')
        joblib.dump(self.scaler, f'{self.model_path}scaler.pkl')
        
        self.logger.info(f"Models saved to {self.model_path}")
    
    def get_feature_importance(self):
        """
        Get which features are most important for anomaly detection
        """
        feature_names = [
            'packet_size', 'ttl', 'ip_len', 'df_flag', 'mf_flag',
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'window_size',
            'tcp_payload_len', 'syn_flag', 'ack_flag', 'fin_flag',
            'rst_flag', 'psh_flag', 'urg_flag', 'udp_src_port',
            'udp_dst_port', 'udp_payload_len', 'icmp_type', 'icmp_code',
            'protocol', 'mean_interval', 'std_interval', 'min_interval',
            'max_interval', 'packet_rate'
        ]
        
        return feature_names


class MLEnhancedIDS:
    """
    Enhanced IDS with ML anomaly detection
    Integrates with existing IDS
    """
    
    def __init__(self, base_ids, ml_detector):
        self.base_ids = base_ids
        self.ml_detector = ml_detector
        self.training_mode = False
        self.training_packets = []
        
    def start_training_mode(self, duration_seconds=300):
        """
        Enter training mode to learn normal traffic patterns
        Run this when you know traffic is normal
        """
        print(f"\n{'='*60}")
        print("ENTERING ML TRAINING MODE")
        print(f"{'='*60}")
        print(f"Duration: {duration_seconds} seconds")
        print("Please ensure only NORMAL traffic during this period!")
        print(f"{'='*60}\n")
        
        self.training_mode = True
        self.training_packets = []
        
        import threading
        def stop_training():
            time.sleep(duration_seconds)
            self.training_mode = False
            print("\n[*] Training mode ended. Processing training data...")
            if len(self.training_packets) > 100:
                self.ml_detector.train_on_normal_traffic(self.training_packets)
                print("[+] ML model trained and ready!\n")
            else:
                print(f"[!] Not enough packets collected ({len(self.training_packets)}). Need at least 100.")
                print("[!] Please generate more traffic and try again.\n")
        
        threading.Thread(target=stop_training, daemon=True).start()
    
    def analyze_packet_with_ml(self, packet):
        """
        Analyze packet with both rule-based and ML detection
        """
        # If in training mode, collect packets
        if self.training_mode:
            self.training_packets.append(packet)
            return
        
        # Run traditional rule-based detection
        self.base_ids.analyze_packet(packet)
        
        # Run ML anomaly detection
        if self.ml_detector.is_trained:
            is_anomaly, score, features = self.ml_detector.detect_anomaly(packet)
            
            if is_anomaly and score > 0.7:  # High confidence anomaly
                # Log ML-detected anomaly
                self._log_ml_anomaly(packet, score, features)
    
    def _log_ml_anomaly(self, packet, score, features):
        """Log ML-detected anomaly"""
        severity = "HIGH" if score > 0.85 else "MEDIUM"
        
        src_ip = packet['IP'].src if packet.haslayer('IP') else "N/A"
        dst_ip = packet['IP'].dst if packet.haslayer('IP') else "N/A"
        src_port = packet['TCP'].sport if packet.haslayer('TCP') else 0
        dst_port = packet['TCP'].dport if packet.haslayer('TCP') else 0
        
        self.base_ids.log_alert(
            severity,
            "ML_ANOMALY",
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            "ML",
            f"ML-detected anomaly (confidence: {score:.2%})",
            str(features[:10] if features is not None else [])
        )
        
        print(f"\n{'='*60}")
        print(f"🤖 ML ANOMALY DETECTED")
        print(f"Confidence: {score:.2%}")
        print(f"Source: {src_ip}:{src_port} → Dest: {dst_ip}:{dst_port}")
        print(f"{'='*60}\n")