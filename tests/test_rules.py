"""
Test rule-based detection
"""

import pytest
import time
from falconx.rules import RuleDetector


def test_syn_detection():
    """Test SYN rate spike detection"""
    detector = RuleDetector()

    # Generate SYN packets
    for i in range(60):
        features = {
            'is_syn': True,
            'is_icmp': False,
            'is_dns': False,
            'protocol': 'tcp',
            'src_ip': '192.168.1.1',
            'dst_port': 80
        }
        detections = detector.detect(features)
        if len(detections) > 0:
            assert detections[0]['type'] == 'syn_rate_spike'
            return

    # Should have detected SYN spike
    assert False, "SYN spike not detected"


def test_icmp_detection():
    """Test ICMP burst detection"""
    detector = RuleDetector()

    # Generate ICMP packets
    for i in range(35):
        features = {
            'is_syn': False,
            'is_icmp': True,
            'is_dns': False,
            'protocol': 'icmp',
            'src_ip': '192.168.1.1'
        }
        detections = detector.detect(features)
        if len(detections) > 0:
            assert detections[0]['type'] == 'icmp_burst'
            return

    # Should have detected ICMP burst
    assert False, "ICMP burst not detected"


def test_dns_detection():
    """Test DNS burst detection"""
    detector = RuleDetector()

    # Generate DNS packets
    for i in range(25):
        features = {
            'is_syn': False,
            'is_icmp': False,
            'is_dns': True,
            'protocol': 'udp',
            'src_ip': '192.168.1.1',
            'dst_port': 53
        }
        detections = detector.detect(features)
        if len(detections) > 0:
            assert detections[0]['type'] == 'dns_burst'
            return

    # Should have detected DNS burst
    assert False, "DNS burst not detected"


def test_port_scan_detection():
    """Test port scan detection"""
    detector = RuleDetector()

    # Simulate port scan from single IP to multiple ports
    for port in range(1, 15):
        features = {
            'is_syn': True,
            'is_icmp': False,
            'is_dns': False,
            'protocol': 'tcp',
            'src_ip': '192.168.1.100',
            'dst_port': port
        }
        detections = detector.detect(features)
        if len(detections) > 0:
            assert detections[0]['type'] == 'port_scan'
            return

    # Should have detected port scan
    assert False, "Port scan not detected"


def test_window_reset():
    """Test detection window reset"""
    detector = RuleDetector()
    detector.syn_count = 100
    detector.window_start = time.time() - 10

    assert detector.check_window_expiration() == True
