"""
Feature extraction from packets
Extracts packet and flow features for detection
"""

import logging
from typing import Dict, Any
from scapy.all import Packet, IP, TCP, UDP, ICMP, DNS
from collections import defaultdict

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from packets"""

    def __init__(self):
        self.flow_features: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def extract_packet_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract features from a single packet"""
        features = {
            'timestamp': float(packet.time),
            'size': len(packet),
            'protocol': 'unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'is_syn': False,
            'is_icmp': False,
            'is_dns': False
        }

        try:
            if IP in packet:
                features['src_ip'] = packet[IP].src
                features['dst_ip'] = packet[IP].dst
                features['protocol'] = packet[IP].proto

                if TCP in packet:
                    features['protocol'] = 'tcp'
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['flags'] = packet[TCP].flags
                    features['is_syn'] = packet[TCP].flags & 0x02  # SYN flag

                elif UDP in packet:
                    features['protocol'] = 'udp'
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport

                    if DNS in packet:
                        features['is_dns'] = True

                elif ICMP in packet:
                    features['protocol'] = 'icmp'
                    features['is_icmp'] = True

        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")

        return features

    def get_flow_key(self, features: Dict[str, Any]) -> str:
        """Generate flow key from features"""
        if not features['src_ip'] or not features['dst_ip']:
            return None

        src = features['src_ip']
        dst = features['dst_ip']
        proto = features['protocol']
        sport = features.get('src_port', 0)
        dport = features.get('dst_port', 0)

        return f"{src}:{sport}-{dst}:{dport}-{proto}"

    def update_flow_features(self, features: Dict[str, Any]):
        """Update flow-level features"""
        flow_key = self.get_flow_key(features)
        if not flow_key:
            return

        if flow_key not in self.flow_features:
            self.flow_features[flow_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'first_seen': features['timestamp'],
                'last_seen': features['timestamp'],
                'syn_count': 0,
                'icmp_count': 0,
                'dns_count': 0
            }

        flow = self.flow_features[flow_key]
        flow['packet_count'] += 1
        flow['byte_count'] += features['size']
        flow['last_seen'] = features['timestamp']

        if features['is_syn']:
            flow['syn_count'] += 1
        if features['is_icmp']:
            flow['icmp_count'] += 1
        if features['is_dns']:
            flow['dns_count'] += 1

    def get_flow_features(self, flow_key: str) -> Dict[str, Any]:
        """Get features for a specific flow"""
        return self.flow_features.get(flow_key, {})

    def cleanup_old_flows(self, max_age_seconds: float = 300.0):
        """Remove flows older than max_age_seconds"""
        import time
        current_time = time.time()
        to_remove = []

        for flow_key, flow in self.flow_features.items():
            if current_time - flow['last_seen'] > max_age_seconds:
                to_remove.append(flow_key)

        for flow_key in to_remove:
            del self.flow_features[flow_key]

        logger.debug(f"Cleaned up {len(to_remove)} old flows")
