# Network Packet Sniffer

A powerful and user-friendly network packet sniffer built with Python and Scapy. This tool captures and analyzes network traffic, providing detailed statistics about protocols, IP addresses, ports, and data transfer patterns.

## Features

- Real-time packet capture and analysis
- Support for TCP, UDP, DNS, and ARP protocols
- Detailed traffic statistics including:
  - Protocol distribution
  - Top IP pairs (source → destination)
  - Most active ports
  - Busiest IP addresses
  - Traffic volume metrics
- Configurable capture settings
- Command-line interface
- Logging capabilities

## Prerequisites

- Python 3.7+
- Root/Administrator privileges (required for packet capture)
- Operating System: Linux, macOS, or Windows

## Installation

1. Clone the repository:
```bash
git clone https://github.com/omarmaaroufoffice/network-packet-sniffer.git
cd network-packet-sniffer
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
```

3. Install requirements:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
# Linux/macOS
sudo ./run_sniffer.sh

# Windows (run as Administrator)
python -m src.sniffer
```

With options:
```bash
# Capture for 30 seconds
sudo ./run_sniffer.sh -t 30

# Capture 100 packets
sudo ./run_sniffer.sh -n 100

# Use specific interface
sudo ./run_sniffer.sh -i eth0

# Apply filter (e.g., only TCP traffic)
sudo ./run_sniffer.sh -f "tcp"
```

Available options:
- `-i, --interface`: Network interface to use
- `-t, --timeout`: Stop after N seconds
- `-n, --count`: Capture N packets
- `-f, --filter`: BPF filter string

## Sample Output

```
=== Packet Sniffer Statistics ===

Protocol Summary:
TCP Packets: 150
UDP Packets: 45
DNS Packets: 20
ARP Packets: 5
Other Packets: 2

Top 10 IP Pairs (Source -> Destination):
192.168.1.100 -> 172.217.167.78: 45 packets
192.168.1.100 -> 8.8.8.8: 20 packets
...
```

## Security Notice

This tool should only be used on networks you own or have explicit permission to monitor. Unauthorized packet sniffing may be illegal in your jurisdiction.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Omar Maarouf (@omarmaaroufoffice)