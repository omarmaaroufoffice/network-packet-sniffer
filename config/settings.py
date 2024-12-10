# Default configuration settings

# Network interface to sniff on (None for default interface)
DEFAULT_INTERFACE = None

# Default packet filter (empty string captures all packets)
DEFAULT_FILTER = ""

# Maximum number of packets to capture (None for unlimited)
MAX_PACKETS = None

# Log settings
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Platform specific settings
import platform
IS_MACOS = platform.system() == "Darwin"
if IS_MACOS:
    # MacOS specific settings
    DEFAULT_FILTER = "not arp"  # Exclude ARP packets on macOS to reduce errors
    MAX_PACKETS = 1000  # Limit packet count on macOS for stability
