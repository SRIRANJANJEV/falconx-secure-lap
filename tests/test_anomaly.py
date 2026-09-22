"""
Test statistical anomaly detection
"""

import pytest
from falconx.anomaly import AnomalyDetector


def test_add_sample():
    """Test adding samples to history"""
    detector = AnomalyDetector()

    metrics = {
        'packet_rate': 100.0,
        'byte_rate': 1000.0,
        'syn_rate': 10.0
    }

    detector.add_sample(metrics)

    assert len(detector.packet_rate_history) == 1
    assert detector.packet_rate_history[0] == 100.0


def test_history_bounding():
    """Test that history is bounded"""
    detector = AnomalyDetector()

    for i in range(150):
        metrics = {
            'packet_rate': float(i),
            'byte_rate': float(i * 10),
            'syn_rate': float(i)
        }
        detector.add_sample(metrics)

    assert len(detector.packet_rate_history) == 100


def test_insufficient_history():
    """Test detection with insufficient history"""
    detector = AnomalyDetector()

    metrics = {'packet_rate': 100.0, 'byte_rate': 1000.0, 'syn_rate': 10.0}
    for i in range(5):
        detector.add_sample(metrics)

    result = detector.detect(metrics)

    assert result['is_anomaly'] == False
    assert result['reason'] == 'Insufficient history'


def test_normal_detection():
    """Test detection with normal metrics"""
    detector = AnomalyDetector()

    # Add normal samples
    for i in range(20):
        metrics = {
            'packet_rate': 100.0 + (i % 10),
            'byte_rate': 1000.0 + (i % 100),
            'syn_rate': 10.0 + (i % 5)
        }
        detector.add_sample(metrics)

    # Test with normal metric
    current_metrics = {'packet_rate': 105.0, 'byte_rate': 1050.0, 'syn_rate': 12.0}
    result = detector.detect(current_metrics)

    assert result['is_anomaly'] == False


def test_anomaly_detection():
    """Test detection with anomalous metrics"""
    detector = AnomalyDetector()

    # Add normal samples
    for i in range(20):
        metrics = {
            'packet_rate': 100.0,
            'byte_rate': 1000.0,
            'syn_rate': 10.0
        }
        detector.add_sample(metrics)

    # Test with anomalous metric (far from mean)
    current_metrics = {'packet_rate': 1000.0, 'byte_rate': 10000.0, 'syn_rate': 100.0}
    result = detector.detect(current_metrics)

    assert result['is_anomaly'] == True
    assert len(result['anomalies']) > 0
