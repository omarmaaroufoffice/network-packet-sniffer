#!/bin/bash

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Run the sniffer
PYTHONPATH=$PYTHONPATH:. python3 -m src.sniffer "$@" 