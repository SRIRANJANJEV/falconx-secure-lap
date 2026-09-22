"""
Rule-based detection module
Implements lightweight local detection rules
"""

import logging
import time
from typing import Dict, Any, List
from collections import defaultdict

logger = logging.getLogger(__name__)


class RuleDetector:
    """Rule-based threat detection"""

    def __init__(self):
        # Detection windows
        self.window_seconds = 5.0

        # Counters for rate-based detection
        self.syn_count = 0
        self.icmp_count = 0
        self.dns_count = 0
        self.window_start = time.time()

        # Port scan detection
        self.connection_attempts: Dict[str, set] = defaultdict(set)
        self.port_scan_threshold = 10

        # Current metrics
        self.current_metrics = {
            'packet_rate': 0.0,
            'syn_rate': 0.0,
            'icmp_rate': 0.0,
            'dns_rate': 0.0
        }

    def reset_window(self):
        """Reset detection window"""
        self.syn_count = 0
        self.icmp_count = 0
        self.dns_count = 0
        self.window_start = time.time()
        self.connection_attempts.clear()

    def update_window(self):
        """Update metrics for current window"""
        elapsed = time.time() - self.window_start
        if elapsed == 0:
            elapsed = 1.0

        self.current_metrics['packet_rate'] = self.syn_count + self.icmp_count + self.dns_count
        self.current_metrics['syn_rate'] = self.syn_count / elapsed
        self.current_metrics['icmp_rate'] = self.icmp_count / elapsed
        self.current_metrics['dns_rate'] = self.dns_count / elapsed

    def detect(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run rule-based detection on packet features"""
        detections = []

        # Update counters
        if features['is_syn']:
            self.syn_count += 1
        if features['is_icmp']:
            self.icmp_count += 1
        if features['is_dns']:
            self.dns_count += 1

        # SYN rate spike detection
        if self.syn_count > 50:  # Threshold: 50 SYN packets in window
            detections.append({
                'type': 'syn_rate_spike',
                'severity': 'high',
                'description': 'High SYN packet rate detected',
                'value': self.syn_count
            })

        # ICMP burst detection
        if self.icmp_count > 30:  # Threshold: 30 ICMP packets in window
            detections.append({
                'type': 'icmp_burst',
                'severity': 'medium',
                'description': 'ICMP burst detected',
                'value': self.icmp_count
            })

        # DNS burst detection
        if self.dns_count > 20:  # Threshold: 20 DNS packets in window
            detections.append({
                'type': 'dns_burst',
                'severity': 'medium',
                'description': 'DNS burst detected',
                'value': self.dns_count
            })

        # Port scan detection
        src_ip = features.get('src_ip')
        dst_port = features.get('dst_port')
        if src_ip and dst_port and features['protocol'] == 'tcp':
            self.connection_attempts[src_ip].add(dst_port)
            if len(self.connection_attempts[src_ip]) > self.port_scan_threshold:
                detections.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'description': f'Port scan behavior from {src_ip}',
                    'value': len(self.connection_attempts[src_ip])
                })

        return detections

    def check_window_expiration(self) -> bool:
        """Check if detection window has expired"""
        return time.time() - self.window_start > self.window_seconds

    def get_current_metrics(self) -> Dict[str, float]:
        """Get current detection metrics"""
        self.update_window()
        return self.current_metrics.copy()
