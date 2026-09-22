"""
Test risk scoring
"""

import pytest
from falconx.risk import RiskScorer


def test_risk_calculation_no_detections():
    """Test risk calculation with no detections"""
    scorer = RiskScorer()
    detections = []
    baseline_result = {'is_anomaly': False}

    risk = scorer.calculate_risk(detections, baseline_result)

    assert risk['score'] == 0
    assert risk['level'] == 'low'
    assert risk['detection_count'] == 0


def test_risk_calculation_low_severity():
    """Test risk calculation with low severity detections"""
    scorer = RiskScorer()
    detections = [
        {'type': 'test', 'severity': 'low'}
    ]
    baseline_result = {'is_anomaly': False}

    risk = scorer.calculate_risk(detections, baseline_result)

    assert risk['score'] == 1
    assert risk['level'] == 'low'


def test_risk_calculation_high_severity():
    """Test risk calculation with high severity detections"""
    scorer = RiskScorer()
    detections = [
        {'type': 'syn_spike', 'severity': 'high'},
        {'type': 'port_scan', 'severity': 'high'}
    ]
    baseline_result = {'is_anomaly': False}

    risk = scorer.calculate_risk(detections, baseline_result)

    assert risk['score'] == 20
    assert risk['level'] == 'high'
    assert risk['max_severity'] == 'high'


def test_risk_calculation_with_baseline_anomaly():
    """Test risk calculation with baseline anomaly"""
    scorer = RiskScorer()
    detections = []
    baseline_result = {'is_anomaly': True, 'anomalies': ['packet_rate_spike']}

    risk = scorer.calculate_risk(detections, baseline_result)

    assert risk['score'] == 5
    assert risk['level'] == 'low'


def test_risk_level_critical():
    """Test critical risk level"""
    scorer = RiskScorer()
    detections = [
        {'type': 'syn_spike', 'severity': 'high'},
        {'type': 'port_scan', 'severity': 'high'},
        {'type': 'dos', 'severity': 'high'},
        {'type': 'injection', 'severity': 'high'},
        {'type': 'scan', 'severity': 'high'},
        {'type': 'flood', 'severity': 'high'},
        {'type': 'attack', 'severity': 'high'},
        {'type': 'exploit', 'severity': 'high'}
    ]
    baseline_result = {'is_anomaly': True, 'anomalies': ['packet_rate_spike']}

    risk = scorer.calculate_risk(detections, baseline_result)

    assert risk['score'] >= 70
    assert risk['level'] == 'critical'


def test_risk_description():
    """Test risk description generation"""
    scorer = RiskScorer()

    assert scorer.get_risk_description('critical') == 'Critical risk - immediate attention required'
    assert scorer.get_risk_description('high') == 'High risk - investigation recommended'
    assert scorer.get_risk_description('medium') == 'Medium risk - monitor closely'
    assert scorer.get_risk_description('low') == 'Low risk - normal operation'
