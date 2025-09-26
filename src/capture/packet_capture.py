#!/usr/bin/env python3

import os
from scapy.all import sniff, wrpcap, conf

class PacketCapture:
    
    def __init__(self, interface, bpf_filter=""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packets = []
        
        if os.geteuid() != 0:
            print("Warn: make sure the program is started with sudo.")
    
    def capture_packet(self, count=1, timeout=None):
        try:
            packets = sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                count=count,
                timeout=timeout
            )
            
            if packets:
                self.packets.extend(packets)
                return packets[0]
            return None
        except Exception as e:
            print(f"Capture error: {str(e)}")
            return []
    
    def save_packet(self, packet, filename):
        try:
            wrpcap(filename, packet, append=True)
        except Exception as e:
            print(f"Saving error: {str(e)}")
    
    def get_packet_count(self):
        return len(self.packets)
    
    def clear_packets(self):
        self.packets = []