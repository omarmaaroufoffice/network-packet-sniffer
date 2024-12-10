from scapy.all import IP, TCP, UDP, DNS, ARP
import logging
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Basic protocol stats
        self.stats = {
            'tcp': 0,
            'udp': 0,
            'dns': 0,
            'arp': 0,
            'other': 0
        }
        # Detailed statistics
        self.ip_pairs = defaultdict(int)  # Count packets between IP pairs
        self.port_stats = defaultdict(int)  # Count packets per port
        self.ip_stats = defaultdict(int)    # Count packets per IP
        self.packet_sizes = []              # List of packet sizes
        self.total_bytes = 0
        self.start_time = None
        self.protocol_stats = defaultdict(int)  # Count packets per protocol

    def get_stats(self):
        """Return current packet statistics"""
        return {
            'basic_stats': self.stats,
            'ip_pairs': dict(sorted(self.ip_pairs.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'total_bytes': self.total_bytes,
            'avg_packet_size': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
            'protocols': dict(self.protocol_stats)
        }

    def print_stats(self):
        """Print detailed statistics"""
        stats = self.get_stats()
        
        print("\n=== Packet Sniffer Statistics ===")
        print("\nProtocol Summary:")
        print(f"TCP Packets: {self.stats['tcp']}")
        print(f"UDP Packets: {self.stats['udp']}")
        print(f"DNS Packets: {self.stats['dns']}")
        print(f"ARP Packets: {self.stats['arp']}")
        print(f"Other Packets: {self.stats['other']}")
        
        print("\nTop 10 IP Pairs (Source -> Destination):")
        for pair, count in stats['ip_pairs'].items():
            print(f"{pair}: {count} packets")
        
        print("\nTop 10 Ports:")
        for port, count in stats['top_ports'].items():
            print(f"Port {port}: {count} packets")
        
        print("\nTop 10 IPs:")
        for ip, count in stats['top_ips'].items():
            print(f"IP {ip}: {count} packets")
        
        print("\nTraffic Summary:")
        print(f"Total Bytes Transferred: {self.total_bytes:,} bytes")
        print(f"Average Packet Size: {stats['avg_packet_size']:.2f} bytes")
        
        print("\nProtocol Distribution:")
        for protocol, count in stats['protocols'].items():
            print(f"{protocol}: {count} packets")

    def analyze_packet(self, packet):
        try:
            if packet is None:
                self.logger.warning("Received None packet")
                return
            
            # Update packet size statistics
            if hasattr(packet, 'len'):
                self.packet_sizes.append(packet.len)
                self.total_bytes += packet.len

            if IP in packet:
                self._analyze_ip_packet(packet)
            elif ARP in packet:
                self._analyze_arp_packet(packet)
                self.stats['arp'] += 1
                self.protocol_stats['ARP'] += 1
            else:
                self.stats['other'] += 1
                self.protocol_stats['OTHER'] += 1
                self.logger.info(f"Other packet type: {packet.summary()}")
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {str(e)}")

    def _analyze_ip_packet(self, packet):
        """Analyze IP packets and their upper-layer protocols"""
        try:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Update IP statistics
            self.ip_stats[ip_src] += 1
            self.ip_stats[ip_dst] += 1
            self.ip_pairs[f"{ip_src} -> {ip_dst}"] += 1

            if TCP in packet:
                tcp_sport = packet[TCP].sport if hasattr(packet[TCP], 'sport') else 0
                tcp_dport = packet[TCP].dport if hasattr(packet[TCP], 'dport') else 0
                self.logger.info(f"TCP: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
                self.stats['tcp'] += 1
                self.protocol_stats['TCP'] += 1
                self.port_stats[tcp_sport] += 1
                self.port_stats[tcp_dport] += 1
            
            elif UDP in packet:
                udp_sport = packet[UDP].sport if hasattr(packet[UDP], 'sport') else 0
                udp_dport = packet[UDP].dport if hasattr(packet[UDP], 'dport') else 0
                
                if DNS in packet:
                    self.logger.info(f"DNS Query: {packet[DNS].summary()}")
                    self.stats['dns'] += 1
                    self.protocol_stats['DNS'] += 1
                else:
                    self.logger.info(f"UDP: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
                    self.stats['udp'] += 1
                    self.protocol_stats['UDP'] += 1
                
                self.port_stats[udp_sport] += 1
                self.port_stats[udp_dport] += 1

        except Exception as e:
            self.logger.error(f"Error processing IP packet: {str(e)}")

    def _analyze_arp_packet(self, packet):
        """Analyze ARP packets"""
        try:
            if hasattr(packet[ARP], 'psrc') and hasattr(packet[ARP], 'pdst'):
                self.logger.info(f"ARP: {packet[ARP].psrc} -> {packet[ARP].pdst}")
                self.ip_pairs[f"{packet[ARP].psrc} -> {packet[ARP].pdst}"] += 1
            else:
                self.logger.warning("Incomplete ARP packet received")
        except Exception as e:
            self.logger.error(f"Error processing ARP packet: {str(e)}")
