"""
Test system state management
"""

import pytest
import time
from falconx.state import SystemState, EngineStatus, ProtectionState


def test_engine_status_transitions():
    """Test engine status transitions"""
    state = SystemState()

    assert state.engine_status == EngineStatus.STOPPED

    state.set_engine_running()
    assert state.engine_status == EngineStatus.RUNNING

    state.set_engine_stopped()
    assert state.engine_status == EngineStatus.STOPPED

    state.set_engine_failed()
    assert state.engine_status == EngineStatus.FAILED


def test_protection_state_transitions():
    """Test protection state transitions"""
    state = SystemState()

    assert state.protection_state == ProtectionState.UNPROTECTED

    state.set_engine_running()
    assert state.protection_state == ProtectionState.PROTECTED

    state.set_protection_degraded()
    assert state.protection_state == ProtectionState.DEGRADED

    state.set_engine_stopped()
    assert state.protection_state == ProtectionState.UNPROTECTED


def test_packet_counting():
    """Test packet counting"""
    state = SystemState()

    for i in range(100):
        state.increment_packet_count()

    assert state.packet_count == 100


def test_incident_counting():
    """Test incident counting"""
    state = SystemState()

    for i in range(5):
        state.increment_incident_count()

    assert state.incident_count == 5


def test_packet_rate_update():
    """Test packet rate update"""
    state = SystemState()

    state.update_packet_rate(100.5)
    assert state.current_packet_rate == 100.5


def test_status_updates():
    """Test various status updates"""
    state = SystemState()

    state.set_ml_status('ACTIVE')
    assert state.ml_status == 'ACTIVE'

    state.set_ai_status('AVAILABLE')
    assert state.ai_status == 'AVAILABLE'

    state.set_firewall_status('ACTIVE')
    assert state.firewall_status == 'ACTIVE'


def test_status_dict():
    """Test status dictionary generation"""
    state = SystemState()
    state.set_engine_running()

    for i in range(10):
        state.increment_packet_count()

    state.increment_incident_count()
    state.set_ml_status('LEARNING')
    state.set_ai_status('UNAVAILABLE')
    state.set_firewall_status('ACTIVE')

    status = state.get_status_dict()

    assert status['engine_status'] == 'RUNNING'
    assert status['protection_state'] == 'PROTECTED'
    assert status['packet_count'] == 10
    assert status['incident_count'] == 1
    assert status['ml_status'] == 'LEARNING'
    assert status['ai_status'] == 'UNAVAILABLE'
    assert status['firewall_status'] == 'ACTIVE'


def test_is_protected():
    """Test protection status check"""
    state = SystemState()

    assert state.is_protected() == False

    state.set_engine_running()
    assert state.is_protected() == True

    state.set_protection_degraded()
    assert state.is_protected() == True

    state.set_engine_stopped()
    assert state.is_protected() == False
