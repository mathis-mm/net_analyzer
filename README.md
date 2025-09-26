# Network Traffic Analyzer (CLI)

A network traffic and packet analyzer developed in Python with a CLI.

## Features

- Real-time network packet capture
- Detailed protocol analysis (TCP, UDP, ICMP, etc.)
- Text-based traffic data display in the terminal
- Packet filtering by protocol, IP address, port, etc.
- Network traffic statistics

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python src/main.py [options]`

## Usage

```
python src/main.py --interface eth0 --filter "tcp" --count 100
```

Or with specific options:

```
python src/main.py -i eth0 -f "tcp" -c 100
```

## Prerequisites

- Python 3.8+
- Administrator privileges (for packet capture)
- Libraries: scapy, pyshark, argparse, colorama (for colored terminal output)