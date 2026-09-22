"""
Test packet capture module
"""

import pytest
from falconx.capture import PacketCapture, get_available_interfaces, detect_suitable_interface, validate_interface


def test_get_available_interfaces():
    """Test getting available interfaces"""
    # This test will work on systems with network interfaces
    interfaces = get_available_interfaces()

    # Should return a list
    assert isinstance(interfaces, list)

    # On most systems, there should be at least one interface
    # But we can't guarantee this in all test environments
    # So we just check it doesn't crash


def test_validate_interface():
    """Test interface validation"""
    # Test with a potentially invalid interface
    result = validate_interface('invalid_interface_12345')
    # Should return False for invalid interface
    assert result == False


def test_capture_initialization():
    """Test packet capture initialization"""
    # This test will fail if no suitable interface is found
    # which is expected on systems without network interfaces

    try:
        capture = PacketCapture()
        assert capture.interface is not None
        assert capture.queue is not None
        assert capture._running == False
    except RuntimeError as e:
        # Expected on systems without network interfaces
        pytest.skip("No suitable network interface found")


def test_capture_initialization_with_interface():
    """Test packet capture initialization with specific interface"""
    # Try with a common interface name
    try:
        capture = PacketCapture('eth0')
        assert capture.interface == 'eth0'
    except RuntimeError as e:
        # Expected if eth0 doesn't exist
        pytest.skip("Interface eth0 not available")


def test_detect_suitable_interface():
    """Test automatic interface detection"""
    interface = detect_suitable_interface()

    # May return None if no suitable interface found
    if interface is not None:
        assert isinstance(interface, str)
        assert len(interface) > 0
    else:
        # No interface found is acceptable in test environments
        pass


def test_capture_queue_size():
    """Test capture queue size"""
    try:
        capture = PacketCapture()
        initial_size = capture.get_queue_size()
        assert initial_size == 0
    except RuntimeError:
        pytest.skip("No suitable network interface found")


def test_capture_running_state():
    """Test capture running state"""
    try:
        capture = PacketCapture()
        assert capture.is_running() == False
    except RuntimeError:
        pytest.skip("No suitable network interface found")
