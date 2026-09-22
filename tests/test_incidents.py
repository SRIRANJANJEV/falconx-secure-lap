"""
Test incident management
"""

import pytest
import time
from falconx.incidents import IncidentManager


def test_incident_creation():
    """Test incident creation"""
    manager = IncidentManager()

    detections = [
        {'type': 'syn_spike', 'severity': 'high'}
    ]
    risk_result = {
        'score': 10,
        'level': 'high'
    }
    features = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'protocol': 'tcp'
    }

    incident = manager.create_incident(detections, risk_result, features)

    assert incident['id'] == 1
    assert incident['risk_level'] == 'high'
    assert incident['source_ip'] == '192.168.1.1'
    assert incident['status'] == 'open'


def test_incident_counter():
    """Test incident counter increment"""
    manager = IncidentManager()

    for i in range(5):
        detections = [{'type': 'test', 'severity': 'low'}]
        risk_result = {'score': 1, 'level': 'low'}
        features = {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocol': 'tcp'}
        manager.create_incident(detections, risk_result, features)

    assert manager.incident_counter == 5
    assert manager.get_incident_count() == 5


def test_recent_incidents():
    """Test getting recent incidents"""
    manager = IncidentManager()

    for i in range(15):
        detections = [{'type': 'test', 'severity': 'low'}]
        risk_result = {'score': 1, 'level': 'low'}
        features = {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocol': 'tcp'}
        manager.create_incident(detections, risk_result, features)

    recent = manager.get_recent_incidents(count=10)
    assert len(recent) == 10


def test_incident_bounded_queue():
    """Test that incident queue is bounded"""
    manager = IncidentManager(max_incidents=5)

    for i in range(10):
        detections = [{'type': 'test', 'severity': 'low'}]
        risk_result = {'score': 1, 'level': 'low'}
        features = {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocol': 'tcp'}
        manager.create_incident(detections, risk_result, features)

    assert manager.get_incident_count() == 5  # Should be bounded


def test_old_incident_cleanup():
    """Test cleanup of old incidents"""
    manager = IncidentManager()

    # Create old incident
    detections = [{'type': 'test', 'severity': 'low'}]
    risk_result = {'score': 1, 'level': 'low'}
    features = {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocol': 'tcp'}

    # Manually set old timestamp
    incident = manager.create_incident(detections, risk_result, features)
    manager.incidents[0]['timestamp'] = time.time() - 4000  # Very old

    # Create new incident
    manager.create_incident(detections, risk_result, features)

    # Cleanup old incidents
    manager.clear_old_incidents(max_age_seconds=3600)

    # Only new incident should remain
    assert manager.get_incident_count() == 1
