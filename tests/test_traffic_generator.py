"""
Test synthetic traffic generator safety
"""

import pytest
import sys
import os

# Add lab directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lab'))

from generate_traffic import is_safe_target


def test_safe_target_localhost():
    """Test localhost is considered safe"""
    assert is_safe_target('localhost') == True
    assert is_safe_target('127.0.0.1') == True


def test_safe_target_private_ip():
    """Test private IPs are considered safe"""
    assert is_safe_target('192.168.1.1') == True
    assert is_safe_target('10.0.0.1') == True
    assert is_safe_target('172.16.0.1') == True


def test_unsafe_target_public_ip():
    """Test public IPs are not considered safe"""
    assert is_safe_target('8.8.8.8') == False
    assert is_safe_target('1.1.1.1') == False
    assert is_safe_target('example.com') == False


def test_safe_target_loopback():
    """Test loopback addresses are safe"""
    assert is_safe_target('127.0.0.1') == True
    assert is_safe_target('127.0.0.2') == True


def test_invalid_target():
    """Test invalid targets return False"""
    assert is_safe_target('not-an-ip') == False
    assert is_safe_target('') == False
