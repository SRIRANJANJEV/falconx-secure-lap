"""
Test baseline learning
"""

import pytest
import time
from falconx.baseline import BaselineLearner


def test_baseline_update():
    """Test baseline update"""
    baseline = BaselineLearner()

    features = {
        'size': 100,
        'is_syn': True,
        'is_icmp': False,
        'is_dns': False,
        'src_ip': '192.168.1.1'
    }

    baseline.update(features)

    assert baseline.total_packets == 1
    assert baseline.total_bytes == 100
    assert baseline.total_syn == 1


def test_baseline_finalization():
    """Test baseline finalization"""
    baseline = BaselineLearner()

    # Add some data
    for i in range(10):
        features = {
            'size': 100,
            'is_syn': True,
            'is_icmp': False,
            'is_dns': False,
            'src_ip': '192.168.1.1'
        }
        baseline.update(features)

    baseline.finalize_baseline()

    assert baseline.is_learning == False
    assert baseline.packet_rate_baseline > 0


def test_new_device_detection():
    """Test new device detection"""
    baseline = BaselineLearner()

    assert baseline.is_new_device('192.168.1.1') == True

    baseline.update({'src_ip': '192.168.1.1', 'size': 100, 'is_syn': False, 'is_icmp': False, 'is_dns': False})

    assert baseline.is_new_device('192.168.1.1') == False
    assert baseline.is_new_device('192.168.1.2') == True


def test_anomaly_detection_during_learning():
    """Test anomaly detection during learning phase"""
    baseline = BaselineLearner()

    current_metrics = {
        'packet_rate': 1000.0,
        'syn_rate': 500.0
    }

    result = baseline.check_anomaly(current_metrics)

    assert result['is_anomaly'] == False
    assert result['reason'] == 'Still learning'


def test_anomaly_detection_after_learning():
    """Test anomaly detection after learning"""
    baseline = BaselineLearner()

    # Learn baseline
    for i in range(10):
        baseline.update({'size': 100, 'is_syn': False, 'is_icmp': False, 'is_dns': False, 'src_ip': '192.168.1.1'})

    baseline.finalize_baseline()

    # Test with normal metrics
    current_metrics = {
        'packet_rate': baseline.packet_rate_baseline,
        'syn_rate': baseline.syn_rate_baseline
    }

    result = baseline.check_anomaly(current_metrics)
    assert result['is_anomaly'] == False

    # Test with anomalous metrics
    current_metrics = {
        'packet_rate': baseline.packet_rate_baseline * 10,
        'syn_rate': baseline.syn_rate_baseline * 10
    }

    result = baseline.check_anomaly(current_metrics)
    assert result['is_anomaly'] == True
