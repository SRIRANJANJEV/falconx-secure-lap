"""
Test enforcement module
"""

import pytest
from falconx.enforcement import EnforcementManager, EnforcementMode


def test_enforcement_initialization():
    """Test enforcement manager initialization"""
    enforcement = EnforcementManager()

    assert enforcement.mode == EnforcementMode.LOG_ONLY
    assert enforcement.is_active == False
    assert len(enforcement.blocked_ips) == 0
    assert len(enforcement.blocked_ports) == 0


def test_enforcement_mode_log_only():
    """Test LOG_ONLY mode"""
    enforcement = EnforcementManager(mode='LOG_ONLY')

    assert enforcement.mode == EnforcementMode.LOG_ONLY

    # Should log but not actually block
    result = enforcement.block_ip('192.168.1.1')
    assert result == True
    assert '192.168.1.1' not in enforcement.blocked_ips  # Not actually blocked in LOG_ONLY mode


def test_enforcement_mode_active():
    """Test ACTIVE mode"""
    enforcement = EnforcementManager(mode='ACTIVE')

    assert enforcement.mode == EnforcementMode.ACTIVE


def test_enforcement_set_mode():
    """Test setting enforcement mode"""
    enforcement = EnforcementManager()

    # Set to ACTIVE
    result = enforcement.set_mode('ACTIVE')
    assert result == True
    assert enforcement.mode == EnforcementMode.ACTIVE

    # Set back to LOG_ONLY
    result = enforcement.set_mode('LOG_ONLY')
    assert result == True
    assert enforcement.mode == EnforcementMode.LOG_ONLY

    # Test invalid mode
    result = enforcement.set_mode('INVALID')
    assert result == False


def test_enforcement_set_mode_variations():
    """Test setting enforcement mode with different string formats"""
    enforcement = EnforcementManager()

    # Test different string formats
    enforcement.set_mode('log-only')
    assert enforcement.mode == EnforcementMode.LOG_ONLY

    enforcement.set_mode('active')
    assert enforcement.mode == EnforcementMode.ACTIVE

    enforcement.set_mode('LOG_ONLY')
    assert enforcement.mode == EnforcementMode.LOG_ONLY

    enforcement.set_mode('ACTIVE')
    assert enforcement.mode == EnforcementMode.ACTIVE


def test_ip_validation():
    """Test IP address validation"""
    enforcement = EnforcementManager()

    # Valid IPs
    assert enforcement._validate_ip('192.168.1.1') == True
    assert enforcement._validate_ip('10.0.0.1') == True
    assert enforcement._validate_ip('127.0.0.1') == True
    assert enforcement._validate_ip('::1') == True

    # Invalid IPs
    assert enforcement._validate_ip('invalid') == False
    assert enforcement._validate_ip('256.256.256.256') == False
    assert enforcement._validate_ip('') == False


def test_port_validation():
    """Test port number validation"""
    enforcement = EnforcementManager()

    # Valid ports
    assert enforcement._validate_port(80) == True
    assert enforcement._validate_port(443) == True
    assert enforcement._validate_port(1) == True
    assert enforcement._validate_port(65535) == True
    assert enforcement._validate_port('80') == True

    # Invalid ports
    assert enforcement._validate_port(0) == False
    assert enforcement._validate_port(65536) == False
    assert enforcement._validate_port(-1) == False
    assert enforcement._validate_port('invalid') == False


def test_block_ip_validation():
    """Test IP blocking with validation"""
    enforcement = EnforcementManager(mode='LOG_ONLY')

    # Valid IP
    result = enforcement.block_ip('192.168.1.1')
    assert result == True

    # Invalid IP
    result = enforcement.block_ip('invalid')
    assert result == False


def test_block_port_validation():
    """Test port blocking with validation"""
    enforcement = EnforcementManager(mode='LOG_ONLY')

    # Valid port
    result = enforcement.block_port(80)
    assert result == True

    # Invalid port
    result = enforcement.block_port(99999)
    assert result == False


def test_unblock_ip():
    """Test IP unblocking"""
    enforcement = EnforcementManager(mode='LOG_ONLY')

    # Should work even in LOG_ONLY mode
    result = enforcement.unblock_ip('192.168.1.1')
    assert result == True


def test_unblock_port():
    """Test port unblocking"""
    enforcement = EnforcementManager(mode='LOG_ONLY')

    # Should work even in LOG_ONLY mode
    result = enforcement.unblock_port(80)
    assert result == True


def test_enforcement_mode_enum():
    """Test EnforcementMode enum"""
    assert EnforcementMode.LOG_ONLY.value == "LOG_ONLY"
    assert EnforcementMode.ACTIVE.value == "ACTIVE"
