"""
Risk scoring module
Calculates risk scores from detection results
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RiskScorer:
    """Calculate risk scores from detections"""

    def __init__(self):
        self.severity_weights = {
            'low': 1,
            'medium': 5,
            'high': 10
        }

    def calculate_risk(self, detections: List[Dict[str, Any]], baseline_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score from detections"""
        total_score = 0
        max_severity = 'low'
        detection_types = []

        for detection in detections:
            severity = detection.get('severity', 'low')
            weight = self.severity_weights.get(severity, 1)
            total_score += weight

            if severity == 'high':
                max_severity = 'high'
            elif severity == 'medium' and max_severity != 'high':
                max_severity = 'medium'

            detection_types.append(detection.get('type', 'unknown'))

        # Add baseline anomaly score
        if baseline_result.get('is_anomaly', False):
            total_score += 5
            max_severity = 'high' if max_severity != 'high' else max_severity
            detection_types.extend(baseline_result.get('anomalies', []))

        # Normalize score to 0-100
        normalized_score = min(total_score, 100)

        # Determine risk level
        if normalized_score >= 70:
            risk_level = 'critical'
        elif normalized_score >= 40:
            risk_level = 'high'
        elif normalized_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'score': normalized_score,
            'level': risk_level,
            'max_severity': max_severity,
            'detection_count': len(detections),
            'detection_types': detection_types
        }

    def get_risk_description(self, risk_level: str) -> str:
        """Get human-readable risk description"""
        descriptions = {
            'critical': 'Critical risk - immediate attention required',
            'high': 'High risk - investigation recommended',
            'medium': 'Medium risk - monitor closely',
            'low': 'Low risk - normal operation'
        }
        return descriptions.get(risk_level, 'Unknown risk level')
