import pytest
from scapy.all import IP, TCP, UDP, DNS, ARP, Ether
from src.packet_analyzer import PacketAnalyzer
import logging

class TestPacketAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return PacketAnalyzer()

    def test_tcp_packet_analysis(self, analyzer):
        packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=80, dport=443)
        analyzer.analyze_packet(packet)
        stats = analyzer.get_stats()
        assert stats['tcp'] == 1
        assert stats['udp'] == 0

    def test_udp_packet_analysis(self, analyzer):
        packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP(sport=53, dport=53)
        analyzer.analyze_packet(packet)
        stats = analyzer.get_stats()
        assert stats['udp'] == 1
        assert stats['tcp'] == 0

    def test_error_handling(self, analyzer):
        # Test with malformed packet
        analyzer.analyze_packet(None)
        # Should not raise exception
