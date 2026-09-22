"""
Incident management module
Creates and tracks security incidents
"""

import logging
import time
import json
import os
from typing import Dict, Any, List
from collections import deque

logger = logging.getLogger(__name__)


class IncidentManager:
    """Manage security incidents"""

    def __init__(self, max_incidents: int = 100, incidents_file='/var/run/falconx-incidents.json'):
        self.max_incidents = max_incidents
        self.incidents: deque = deque(maxlen=max_incidents)
        self.incident_counter = 0
        self.incidents_file = incidents_file

    def create_incident(self, detections: List[Dict[str, Any]], risk_result: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident from detections"""
        self.incident_counter += 1

        incident = {
            'id': self.incident_counter,
            'timestamp': time.time(),
            'detections': detections,
            'risk_score': risk_result['score'],
            'risk_level': risk_result['level'],
            'source_ip': features.get('src_ip'),
            'destination_ip': features.get('dst_ip'),
            'protocol': features.get('protocol'),
            'description': self._generate_description(detections, risk_result),
            'status': 'open'
        }

        self.incidents.append(incident)
        logger.warning(f"Incident #{incident['id']} created: {incident['description']}")
        return incident

    def _generate_description(self, detections: List[Dict[str, Any]], risk_result: Dict[str, Any]) -> str:
        """Generate human-readable incident description"""
        if not detections:
            return f"Risk level: {risk_result['level']}"

        detection_types = [d.get('type', 'unknown') for d in detections]
        return f"Detected: {', '.join(detection_types)} - Risk: {risk_result['level']}"

    def get_recent_incidents(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent incidents"""
        return list(self.incidents)[-count:]

    def get_incident_count(self) -> int:
        """Get total incident count"""
        return len(self.incidents)

    def get_incident_by_id(self, incident_id: int) -> Dict[str, Any]:
        """Get specific incident by ID"""
        for incident in self.incidents:
            if incident['id'] == incident_id:
                return incident
        return None

    def clear_old_incidents(self, max_age_seconds: float = 3600.0):
        """Clear incidents older than max_age_seconds"""
        current_time = time.time()
        while self.incidents and current_time - self.incidents[0]['timestamp'] > max_age_seconds:
            self.incidents.popleft()

    def save_incidents(self):
        """Save incidents to file for dashboard communication"""
        try:
            incidents_data = {
                'incidents': list(self.incidents),
                'count': len(self.incidents)
            }

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.incidents_file), exist_ok=True)

            with open(self.incidents_file, 'w') as f:
                json.dump(incidents_data, f)
        except Exception as e:
            logger.error(f"Error saving incidents: {e}")

    def remove_incidents_file(self):
        """Remove incidents file on shutdown"""
        try:
            if os.path.exists(self.incidents_file):
                os.remove(self.incidents_file)
        except Exception as e:
            logger.error(f"Error removing incidents file: {e}")
