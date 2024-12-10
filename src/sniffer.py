from scapy.all import sniff, TCP, IP, conf
from src.packet_analyzer import PacketAnalyzer
import logging
import argparse
from src.utils.packet_utils import setup_logging
from config.settings import DEFAULT_INTERFACE, DEFAULT_FILTER, MAX_PACKETS

class PacketSniffer:
    def __init__(self, interface=DEFAULT_INTERFACE):
        self.interface = interface
        self.analyzer = PacketAnalyzer()
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Configure Scapy settings for better compatibility
        conf.sniff_promisc = False
        if interface:
            conf.iface = interface

    def packet_callback(self, packet):
        try:
            if packet is None:
                return
            if not hasattr(packet, 'time'):
                return
            self.analyzer.analyze_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")

    def start_sniffing(self, filter=DEFAULT_FILTER, packet_count=MAX_PACKETS, timeout=None):
        """
        Start sniffing packets on the specified interface
        Args:
            filter (str): BPF filter string
            packet_count (int): Number of packets to capture (None for unlimited)
            timeout (int): Number of seconds to sniff (None for unlimited)
        """
        self.logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        self.logger.info(f"Using filter: {filter or 'none'}")
        if timeout:
            self.logger.info(f"Will stop after {timeout} seconds")
        if packet_count:
            self.logger.info(f"Will capture {packet_count} packets")
        
        try:
            sniff(
                iface=self.interface,
                filter=filter,
                prn=self.packet_callback,
                store=False,
                count=packet_count,
                timeout=timeout,
                L2socket=None
            )
            self.logger.info("Packet capture completed")
            self.analyzer.print_stats()
        except KeyboardInterrupt:
            self.logger.info("Packet capture stopped by user")
            self.analyzer.print_stats()
        except Exception as e:
            self.logger.error(f"Sniffing failed: {str(e)}")
            self.logger.debug("Error details:", exc_info=True)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Network Packet Sniffer')
        parser.add_argument('-i', '--interface', help='Network interface to use')
        parser.add_argument('-t', '--timeout', type=int, help='Stop after N seconds')
        parser.add_argument('-n', '--count', type=int, help='Capture N packets')
        parser.add_argument('-f', '--filter', help='BPF filter string')
        args = parser.parse_args()

        # List available interfaces
        from scapy.all import get_if_list
        interfaces = get_if_list()
        print("Available interfaces:", interfaces)
        
        # Determine interface to use
        interface = args.interface or ('en0' if 'en0' in interfaces else interfaces[0])
        print(f"Using interface: {interface}")
        
        sniffer = PacketSniffer(interface=interface)
        sniffer.start_sniffing(
            filter=args.filter or DEFAULT_FILTER,
            packet_count=args.count or MAX_PACKETS,
            timeout=args.timeout
        )
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}", exc_info=True)
