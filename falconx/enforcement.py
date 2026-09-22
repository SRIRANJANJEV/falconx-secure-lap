"""
Enforcement module for nftables
Handles firewall enforcement with privileged operations
"""

import logging
import subprocess
import ipaddress
from typing import Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class EnforcementMode(Enum):
    """Enforcement mode enumeration"""
    LOG_ONLY = "LOG_ONLY"
    ACTIVE = "ACTIVE"


class EnforcementManager:
    """Manage nftables enforcement"""

    def __init__(self, mode: str = 'LOG_ONLY'):
        self.mode = EnforcementMode.LOG_ONLY
        self.is_active = False
        self.blocked_ips = set()
        self.blocked_ports = set()

        # Set initial mode
        self.set_mode(mode)

    def set_mode(self, mode: str) -> bool:
        """Set enforcement mode"""
        try:
            if isinstance(mode, str):
                mode = mode.upper()
                if mode == 'LOG-ONLY':
                    mode = 'LOG_ONLY'
                self.mode = EnforcementMode[mode]
            elif isinstance(mode, EnforcementMode):
                self.mode = mode
            else:
                logger.error(f"Invalid enforcement mode: {mode}")
                return False

            logger.info(f"Enforcement mode set to: {self.mode.value}")
            return True
        except KeyError:
            logger.error(f"Invalid enforcement mode: {mode}")
            return False

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

    def _validate_port(self, port: int) -> bool:
        """Validate port number"""
        if not isinstance(port, int):
            try:
                port = int(port)
            except ValueError:
                return False

        if 1 <= port <= 65535:
            return True
        else:
            logger.error(f"Invalid port number: {port}")
            return False

    def block_ip(self, ip: str) -> bool:
        """Block an IP address using nftables"""
        if not self._validate_ip(ip):
            return False

        if self.mode != EnforcementMode.ACTIVE:
            logger.info(f"Would block {ip} (LOG_ONLY mode)")
            return True

        try:
            # Use nftables to block IP
            cmd = ['nft', 'add', 'rule', 'ip', 'filter', 'input', 'ip', 'saddr', ip, 'drop']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)

            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("nftables command timed out")
            return False
        except Exception as e:
            logger.error(f"Error blocking IP: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        if not self._validate_ip(ip):
            return False

        if self.mode != EnforcementMode.ACTIVE:
            logger.info(f"Would unblock {ip} (LOG_ONLY mode)")
            return True

        try:
            cmd = ['nft', 'delete', 'rule', 'ip', 'filter', 'input', 'ip', 'saddr', ip, 'drop']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)

            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                logger.info(f"Unblocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error unblocking IP: {e}")
            return False

    def block_port(self, port: int) -> bool:
        """Block a port using nftables"""
        if not self._validate_port(port):
            return False

        if self.mode != EnforcementMode.ACTIVE:
            logger.info(f"Would block port {port} (LOG_ONLY mode)")
            return True

        try:
            cmd = ['nft', 'add', 'rule', 'ip', 'filter', 'input', 'tcp', 'dport', str(port), 'drop']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)

            if result.returncode == 0:
                self.blocked_ports.add(port)
                logger.info(f"Blocked port: {port}")
                return True
            else:
                logger.error(f"Failed to block port {port}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("nftables command timed out")
            return False
        except Exception as e:
            logger.error(f"Error blocking port: {e}")
            return False

    def unblock_port(self, port: int) -> bool:
        """Unblock a port"""
        if not self._validate_port(port):
            return False

        if self.mode != EnforcementMode.ACTIVE:
            logger.info(f"Would unblock port {port} (LOG_ONLY mode)")
            return True

        try:
            cmd = ['nft', 'delete', 'rule', 'ip', 'filter', 'input', 'tcp', 'dport', str(port), 'drop']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)

            if result.returncode == 0:
                self.blocked_ports.discard(port)
                logger.info(f"Unblocked port: {port}")
                return True
            else:
                logger.error(f"Failed to unblock port {port}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error unblocking port: {e}")
            return False

    def get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status"""
        try:
            result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, timeout=10)
            return {
                'active': result.returncode == 0,
                'mode': self.mode,
                'ruleset': result.stdout if result.returncode == 0 else 'error'
            }
        except Exception as e:
            logger.error(f"Error getting firewall status: {e}")
            return {
                'active': False,
                'mode': self.mode,
                'ruleset': 'error'
            }

    def init_firewall(self) -> bool:
        """Initialize nftables ruleset"""
        if self.mode != 'active':
            logger.info("Firewall initialization skipped (log-only mode)")
            return True

        try:
            # Create basic nftables ruleset
            cmds = [
                ['nft', 'add', 'table', 'ip', 'filter'],
                ['nft', 'add', 'chain', 'ip', 'filter', 'input', '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', 'policy', 'accept', '}'],
                ['nft', 'add', 'chain', 'ip', 'filter', 'forward', '{', 'type', 'filter', 'hook', 'forward', 'priority', '0', ';', 'policy', 'accept', '}'],
                ['nft', 'add', 'chain', 'ip', 'filter', 'output', '{', 'type', 'filter', 'hook', 'output', 'priority', '0', ';', 'policy', 'accept', '}']
            ]

            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)

            self.is_active = True
            logger.info("Firewall initialized")
            return True

        except Exception as e:
            logger.error(f"Error initializing firewall: {e}")
            return False
