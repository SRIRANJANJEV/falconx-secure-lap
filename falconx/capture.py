"""
Packet capture module using Scapy
Handles network packet capture with bounded queues
"""

import threading
import queue
import logging
import subprocess
from typing import Optional, Callable, List
from scapy.all import sniff, Packet, get_if_list
from scapy.error import Scapy_Exception

logger = logging.getLogger(__name__)


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        logger.info(f"Available interfaces: {interfaces}")
        return interfaces
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return []


def detect_suitable_interface() -> Optional[str]:
    """Detect a suitable network interface for capture"""
    interfaces = get_available_interfaces()

    # Priority order for interface selection
    priority_patterns = ['eth0', 'enp', 'ens', 'wlan0', 'wlp', 'wls']

    for pattern in priority_patterns:
        for iface in interfaces:
            if iface.startswith(pattern):
                logger.info(f"Detected suitable interface: {iface}")
                return iface

    # If no priority interface found, return first available
    if interfaces:
        logger.info(f"Using first available interface: {interfaces[0]}")
        return interfaces[0]

    logger.error("No suitable network interface found")
    return None


def validate_interface(interface: str) -> bool:
    """Validate that an interface exists and is suitable"""
    try:
        interfaces = get_available_interfaces()
        return interface in interfaces
    except Exception as e:
        logger.error(f"Error validating interface: {e}")
        return False


class PacketCapture:
    """Threaded packet capture with bounded queue"""

    def __init__(self, interface: str = None, queue_size: int = 1000):
        # Auto-detect interface if not provided
        if interface is None:
            interface = detect_suitable_interface()
            if interface is None:
                raise RuntimeError("No suitable network interface found")

        if not validate_interface(interface):
            raise RuntimeError(f"Invalid network interface: {interface}")

        self.interface = interface
        self.queue: queue.Queue[Packet] = queue.Queue(maxsize=queue_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[Packet], None]] = None

    def _packet_handler(self, packet: Packet):
        """Handle captured packet"""
        try:
            if not self.queue.full():
                self.queue.put(packet, block=False)
            else:
                logger.warning("Packet queue full, dropping packet")
        except Exception as e:
            logger.error(f"Error handling packet: {e}")

    def start(self):
        """Start packet capture thread"""
        if self._running:
            logger.warning("Capture already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info(f"Packet capture started on {self.interface}")

    def _capture_loop(self):
        """Capture loop running in thread"""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda p: not self._running
            )
        except Scapy_Exception as e:
            logger.error(f"Scapy capture error: {e}")
            self._running = False
        except Exception as e:
            logger.error(f"Unexpected capture error: {e}")
            self._running = False

    def stop(self):
        """Stop packet capture"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Packet capture stopped")

    def get_packet(self, timeout: float = 1.0) -> Optional[Packet]:
        """Get packet from queue with timeout"""
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def is_running(self) -> bool:
        """Check if capture is running"""
        return self._running

    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.queue.qsize()
