"""
System state management
Tracks engine status and protection state
"""

import logging
import time
import json
import os
from typing import Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class EngineStatus(Enum):
    """Engine status enumeration"""
    STOPPED = "STOPPED"
    RUNNING = "RUNNING"
    FAILED = "FAILED"


class ProtectionState(Enum):
    """Protection state enumeration"""
    UNPROTECTED = "UNPROTECTED"
    DEGRADED = "DEGRADED"
    PROTECTED = "PROTECTED"


class SystemState:
    """Manage system state"""

    def __init__(self, state_file='/var/run/falconx-state.json'):
        self.state_file = state_file
        self.engine_status = EngineStatus.STOPPED
        self.protection_state = ProtectionState.UNPROTECTED
        self.start_time = None
        self.packet_count = 0
        self.incident_count = 0
        self.last_packet_time = None
        self.current_packet_rate = 0.0
        self.ml_status = "UNAVAILABLE"
        self.ai_status = "UNAVAILABLE"
        self.firewall_status = "INACTIVE"
        self.interface = "unknown"

    def set_engine_running(self):
        """Set engine to running state"""
        self.engine_status = EngineStatus.RUNNING
        self.start_time = time.time()
        self.protection_state = ProtectionState.PROTECTED
        logger.info("Engine status: RUNNING")

    def set_engine_stopped(self):
        """Set engine to stopped state"""
        self.engine_status = EngineStatus.STOPPED
        self.protection_state = ProtectionState.UNPROTECTED
        logger.info("Engine status: STOPPED")

    def set_engine_failed(self):
        """Set engine to failed state"""
        self.engine_status = EngineStatus.FAILED
        self.protection_state = ProtectionState.UNPROTECTED
        logger.error("Engine status: FAILED")

    def set_protection_degraded(self):
        """Set protection to degraded state"""
        self.protection_state = ProtectionState.DEGRADED
        logger.warning("Protection state: DEGRADED")

    def increment_packet_count(self):
        """Increment packet counter"""
        self.packet_count += 1
        self.last_packet_time = time.time()

    def increment_incident_count(self):
        """Increment incident counter"""
        self.incident_count += 1

    def update_packet_rate(self, rate: float):
        """Update current packet rate"""
        self.current_packet_rate = rate

    def set_ml_status(self, status: str):
        """Set ML status"""
        self.ml_status = status

    def set_ai_status(self, status: str):
        """Set AI status"""
        self.ai_status = status

    def set_firewall_status(self, status: str):
        """Set firewall status"""
        self.firewall_status = status

    def set_interface(self, interface: str):
        """Set network interface"""
        self.interface = interface

    def save_state(self):
        """Save state to file for dashboard communication"""
        try:
            state_dict = self.get_status_dict()
            state_dict['interface'] = self.interface
            state_dict['start_time'] = self.start_time

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)

            with open(self.state_file, 'w') as f:
                json.dump(state_dict, f)
        except Exception as e:
            logger.error(f"Error saving state: {e}")

    def remove_state_file(self):
        """Remove state file on shutdown"""
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
        except Exception as e:
            logger.error(f"Error removing state file: {e}")

    def get_status_dict(self) -> Dict[str, Any]:
        """Get system status as dictionary"""
        return {
            'engine_status': self.engine_status.value,
            'protection_state': self.protection_state.value,
            'uptime': time.time() - self.start_time if self.start_time else 0,
            'packet_count': self.packet_count,
            'incident_count': self.incident_count,
            'current_packet_rate': self.current_packet_rate,
            'ml_status': self.ml_status,
            'ai_status': self.ai_status,
            'firewall_status': self.firewall_status
        }

    def is_protected(self) -> bool:
        """Check if system is protected"""
        return self.protection_state in [ProtectionState.PROTECTED, ProtectionState.DEGRADED]
