"""
Statistical anomaly detection module
Detects deviations from baseline using statistical methods
"""

import logging
from typing import Dict, Any
import statistics

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Statistical anomaly detection"""

    def __init__(self):
        self.history_window = 100
        self.packet_rate_history = []
        self.byte_rate_history = []
        self.syn_rate_history = []

    def add_sample(self, metrics: Dict[str, float]):
        """Add metrics sample to history"""
        self.packet_rate_history.append(metrics.get('packet_rate', 0))
        self.byte_rate_history.append(metrics.get('byte_rate', 0))
        self.syn_rate_history.append(metrics.get('syn_rate', 0))

        # Keep history bounded
        if len(self.packet_rate_history) > self.history_window:
            self.packet_rate_history.pop(0)
            self.byte_rate_history.pop(0)
            self.syn_rate_history.pop(0)

    def detect(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Detect statistical anomalies"""
        if len(self.packet_rate_history) < 10:
            return {'is_anomaly': False, 'reason': 'Insufficient history'}

        anomalies = []

        # Calculate statistics
        try:
            packet_mean = statistics.mean(self.packet_rate_history)
            packet_stdev = statistics.stdev(self.packet_rate_history) if len(self.packet_rate_history) > 1 else 0

            syn_mean = statistics.mean(self.syn_rate_history)
            syn_stdev = statistics.stdev(self.syn_rate_history) if len(self.syn_rate_history) > 1 else 0

            # Check packet rate anomaly (3 sigma)
            current_packet_rate = current_metrics.get('packet_rate', 0)
            if packet_stdev > 0 and current_packet_rate > packet_mean + 3 * packet_stdev:
                anomalies.append({
                    'type': 'packet_rate_anomaly',
                    'severity': 'high',
                    'description': f'Packet rate {current_packet_rate:.2f} exceeds baseline ({packet_mean:.2f} ± {packet_stdev:.2f})',
                    'value': current_packet_rate
                })

            # Check SYN rate anomaly (3 sigma)
            current_syn_rate = current_metrics.get('syn_rate', 0)
            if syn_stdev > 0 and current_syn_rate > syn_mean + 3 * syn_stdev:
                anomalies.append({
                    'type': 'syn_rate_anomaly',
                    'severity': 'high',
                    'description': f'SYN rate {current_syn_rate:.2f} exceeds baseline ({syn_mean:.2f} ± {syn_stdev:.2f})',
                    'value': current_syn_rate
                })

        except statistics.StatisticsError as e:
            logger.error(f"Statistics error: {e}")
            return {'is_anomaly': False, 'reason': 'Statistics error'}

        return {
            'is_anomaly': len(anomalies) > 0,
            'anomalies': anomalies
        }
