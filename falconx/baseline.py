"""
Baseline learning module
Maintains normal network behavior baseline
"""

import logging
import time
from typing import Dict, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class BaselineLearner:
    """Learn and maintain network baseline"""

    def __init__(self, learning_window_seconds: int = 300):
        self.learning_window = learning_window_seconds
        self.start_time = time.time()
        self.is_learning = True

        # Baseline metrics
        self.packet_rate_baseline = 0.0
        self.byte_rate_baseline = 0.0
        self.syn_rate_baseline = 0.0
        self.icmp_rate_baseline = 0.0
        self.dns_rate_baseline = 0.0

        # Accumulators
        self.total_packets = 0
        self.total_bytes = 0
        self.total_syn = 0
        self.total_icmp = 0
        self.total_dns = 0

        # Per-device baselines
        self.device_baselines: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def update(self, features: Dict[str, Any]):
        """Update baseline with packet features"""
        if not self.is_learning:
            return

        self.total_packets += 1
        self.total_bytes += features['size']

        if features['is_syn']:
            self.total_syn += 1
        if features['is_icmp']:
            self.total_icmp += 1
        if features['is_dns']:
            self.total_dns += 1

        # Update per-device baseline
        src_ip = features.get('src_ip')
        if src_ip:
            if src_ip not in self.device_baselines:
                self.device_baselines[src_ip] = {
                    'packet_count': 0,
                    'byte_count': 0,
                    'syn_count': 0,
                    'first_seen': time.time()
                }

            self.device_baselines[src_ip]['packet_count'] += 1
            self.device_baselines[src_ip]['byte_count'] += features['size']
            if features['is_syn']:
                self.device_baselines[src_ip]['syn_count'] += 1

    def finalize_baseline(self):
        """Finalize baseline after learning period"""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            elapsed = 1.0

        self.packet_rate_baseline = self.total_packets / elapsed
        self.byte_rate_baseline = self.total_bytes / elapsed
        self.syn_rate_baseline = self.total_syn / elapsed
        self.icmp_rate_baseline = self.total_icmp / elapsed
        self.dns_rate_baseline = self.total_dns / elapsed

        self.is_learning = False
        logger.info(f"Baseline finalized: {self.packet_rate_baseline:.2f} pkt/s, "
                   f"{self.syn_rate_baseline:.2f} SYN/s, "
                   f"{self.icmp_rate_baseline:.2f} ICMP/s")

    def check_anomaly(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Check if current metrics deviate from baseline"""
        if self.is_learning:
            return {'is_anomaly': False, 'reason': 'Still learning'}

        anomalies = []

        # Check packet rate
        if current_metrics.get('packet_rate', 0) > self.packet_rate_baseline * 3:
            anomalies.append('packet_rate_spike')

        # Check SYN rate
        if current_metrics.get('syn_rate', 0) > self.syn_rate_baseline * 5:
            anomalies.append('syn_rate_spike')

        # Check ICMP rate
        if current_metrics.get('icmp_rate', 0) > self.icmp_rate_baseline * 5:
            anomalies.append('icmp_rate_spike')

        # Check DNS rate
        if current_metrics.get('dns_rate', 0) > self.dns_rate_baseline * 5:
            anomalies.append('dns_rate_spike')

        return {
            'is_anomaly': len(anomalies) > 0,
            'anomalies': anomalies,
            'baseline': {
                'packet_rate': self.packet_rate_baseline,
                'syn_rate': self.syn_rate_baseline,
                'icmp_rate': self.icmp_rate_baseline,
                'dns_rate': self.dns_rate_baseline
            }
        }

    def is_new_device(self, ip: str) -> bool:
        """Check if device is new/unknown"""
        return ip not in self.device_baselines

    def get_device_info(self, ip: str) -> Dict[str, Any]:
        """Get baseline info for a device"""
        return self.device_baselines.get(ip, {})
