#!/usr/bin/env python3
"""
FALCON-X Validation Script
Basic validation of components and imports
"""

import sys
import os

def validate_imports():
    """Validate all core imports"""
    print("Validating imports...")

    try:
        from falconx import capture, features, baseline, rules, anomaly, ml_interface, risk, incidents, enforcement, state, main
        print("[OK] All core imports successful")
        return True
    except ImportError as e:
        print(f"[FAIL] Import error: {e}")
        return False

def validate_components():
    """Validate component instantiation"""
    print("\nValidating components...")

    try:
        from falconx.features import FeatureExtractor
        extractor = FeatureExtractor()
        print("[OK] FeatureExtractor instantiated")

        from falconx.baseline import BaselineLearner
        baseline = BaselineLearner()
        print("[OK] BaselineLearner instantiated")

        from falconx.rules import RuleDetector
        detector = RuleDetector()
        print("[OK] RuleDetector instantiated")

        from falconx.anomaly import AnomalyDetector
        anomaly = AnomalyDetector()
        print("[OK] AnomalyDetector instantiated")

        from falconx.ml_interface import MLInterface
        ml = MLInterface()
        print("[OK] MLInterface instantiated")

        from falconx.risk import RiskScorer
        scorer = RiskScorer()
        print("[OK] RiskScorer instantiated")

        from falconx.incidents import IncidentManager
        manager = IncidentManager()
        print("[OK] IncidentManager instantiated")

        from falconx.enforcement import EnforcementManager
        enforcement = EnforcementManager()
        print("[OK] EnforcementManager instantiated")

        from falconx.state import SystemState
        state = SystemState()
        print("[OK] SystemState instantiated")

        return True
    except Exception as e:
        print(f"[FAIL] Component error: {e}")
        return False

def validate_feature_extraction():
    """Validate feature extraction"""
    print("\nValidating feature extraction...")

    try:
        from falconx.features import FeatureExtractor

        extractor = FeatureExtractor()

        # Test with mock features instead of Scapy packet
        mock_features = {
            'timestamp': 1000.0,
            'size': 100,
            'protocol': 'tcp',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'src_port': 12345,
            'dst_port': 80,
            'flags': 'S',
            'is_syn': True,
            'is_icmp': False,
            'is_dns': False
        }

        # Test flow key generation
        flow_key = extractor.get_flow_key(mock_features)
        assert flow_key is not None

        # Test flow features update
        extractor.update_flow_features(mock_features)
        flow = extractor.get_flow_features(flow_key)
        assert flow['packet_count'] == 1

        print("[OK] Feature extraction working")
        return True
    except Exception as e:
        print(f"[FAIL] Feature extraction error: {e}")
        return False

def validate_rule_detection():
    """Validate rule detection"""
    print("\nValidating rule detection...")

    try:
        from falconx.rules import RuleDetector

        detector = RuleDetector()
        features = {
            'is_syn': True,
            'is_icmp': False,
            'is_dns': False,
            'protocol': 'tcp',
            'src_ip': '192.168.1.1',
            'dst_port': 80
        }

        detections = detector.detect(features)
        print(f"[OK] Rule detection working (detections: {len(detections)})")
        return True
    except Exception as e:
        print(f"[FAIL] Rule detection error: {e}")
        return False

def validate_risk_scoring():
    """Validate risk scoring"""
    print("\nValidating risk scoring...")

    try:
        from falconx.risk import RiskScorer

        scorer = RiskScorer()
        detections = [{'type': 'test', 'severity': 'high'}]
        baseline_result = {'is_anomaly': False}

        risk = scorer.calculate_risk(detections, baseline_result)

        assert risk['score'] > 0
        assert risk['level'] in ['low', 'medium', 'high', 'critical']

        print(f"[OK] Risk scoring working (score: {risk['score']}, level: {risk['level']})")
        return True
    except Exception as e:
        print(f"[FAIL] Risk scoring error: {e}")
        return False

def validate_incident_management():
    """Validate incident management"""
    print("\nValidating incident management...")

    try:
        from falconx.incidents import IncidentManager

        manager = IncidentManager()
        detections = [{'type': 'test', 'severity': 'high'}]
        risk_result = {'score': 10, 'level': 'high'}
        features = {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'protocol': 'tcp'}

        incident = manager.create_incident(detections, risk_result, features)

        assert incident['id'] == 1
        assert incident['risk_level'] == 'high'

        print(f"[OK] Incident management working (incident #{incident['id']})")
        return True
    except Exception as e:
        print(f"[FAIL] Incident management error: {e}")
        return False

def validate_state_management():
    """Validate state management"""
    print("\nValidating state management...")

    try:
        from falconx.state import SystemState

        state = SystemState()
        state.set_engine_running()

        assert state.engine_status.value == 'RUNNING'
        assert state.protection_state.value == 'PROTECTED'

        status = state.get_status_dict()
        assert 'engine_status' in status
        assert 'protection_state' in status

        print("[OK] State management working")
        return True
    except Exception as e:
        print(f"[FAIL] State management error: {e}")
        return False

def main():
    """Run all validations"""
    print("=" * 50)
    print("FALCON-X Validation")
    print("=" * 50)

    results = []

    results.append(("Imports", validate_imports()))
    results.append(("Components", validate_components()))
    results.append(("Feature Extraction", validate_feature_extraction()))
    results.append(("Rule Detection", validate_rule_detection()))
    results.append(("Risk Scoring", validate_risk_scoring()))
    results.append(("Incident Management", validate_incident_management()))
    results.append(("State Management", validate_state_management()))

    print("\n" + "=" * 50)
    print("Validation Results")
    print("=" * 50)

    passed = 0
    failed = 0

    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print("=" * 50)
    print(f"Total: {passed} passed, {failed} failed")
    print("=" * 50)

    return failed == 0

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
