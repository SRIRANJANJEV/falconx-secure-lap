"""
Test feature extraction
"""

import pytest
from falconx.features import FeatureExtractor
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR


def test_extract_packet_features_tcp():
    """Test TCP packet feature extraction"""
    extractor = FeatureExtractor()
    packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80, flags="S")

    features = extractor.extract_packet_features(packet)

    assert features['src_ip'] == "192.168.1.1"
    assert features['dst_ip'] == "192.168.1.2"
    assert features['protocol'] == 'tcp'
    assert features['src_port'] == 12345
    assert features['dst_port'] == 80
    assert features['is_syn'] == True


def test_extract_packet_features_icmp():
    """Test ICMP packet feature extraction"""
    extractor = FeatureExtractor()
    packet = IP(src="192.168.1.1", dst="192.168.1.2")/ICMP()

    features = extractor.extract_packet_features(packet)

    assert features['protocol'] == 'icmp'
    assert features['is_icmp'] == True


def test_extract_packet_features_dns():
    """Test DNS packet feature extraction"""
    extractor = FeatureExtractor()
    packet = IP(src="192.168.1.1", dst="192.168.1.2")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))

    features = extractor.extract_packet_features(packet)

    assert features['protocol'] == 'udp'
    assert features['dst_port'] == 53
    assert features['is_dns'] == True


def test_flow_key_generation():
    """Test flow key generation"""
    extractor = FeatureExtractor()
    features = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'protocol': 'tcp',
        'src_port': 12345,
        'dst_port': 80
    }

    flow_key = extractor.get_flow_key(features)
    assert flow_key == "192.168.1.1:12345-192.168.1.2:80-tcp"


def test_flow_features_update():
    """Test flow feature updates"""
    extractor = FeatureExtractor()
    features = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'protocol': 'tcp',
        'src_port': 12345,
        'dst_port': 80,
        'size': 100,
        'timestamp': 1000.0,
        'is_syn': True,
        'is_icmp': False,
        'is_dns': False
    }

    extractor.update_flow_features(features)
    flow_key = extractor.get_flow_key(features)
    flow = extractor.get_flow_features(flow_key)

    assert flow['packet_count'] == 1
    assert flow['byte_count'] == 100
    assert flow['syn_count'] == 1
