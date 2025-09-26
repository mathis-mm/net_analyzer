#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from colorama import Fore, Back, Style
from tabulate import tabulate

class Display:
    """Class for displaying data in the terminal"""
    
    def __init__(self):
        """Initialize the display"""
        self.protocol_colors = {
            'TCP': Fore.GREEN,
            'UDP': Fore.BLUE,
            'ICMP': Fore.RED,
            'ARP': Fore.MAGENTA,
            'IP': Fore.CYAN,
            'Ethernet': Fore.YELLOW
        }
    
    def show_banner(self):
        """Display the application banner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Fore.GREEN}███╗   ██╗███████╗████████╗    █████╗ ███╗   ██╗ █████╗ {Fore.CYAN}      ║
║ {Fore.GREEN}████╗  ██║██╔════╝╚══██╔══╝   ██╔══██╗████╗  ██║██╔══██╗{Fore.CYAN}      ║
║ {Fore.GREEN}██╔██╗ ██║█████╗     ██║█████╗███████║██╔██╗ ██║███████║{Fore.CYAN}      ║
║ {Fore.GREEN}██║╚██╗██║██╔══╝     ██║╚════╝██╔══██║██║╚██╗██║██╔══██║{Fore.CYAN}      ║
║ {Fore.GREEN}██║ ╚████║███████╗   ██║      ██║  ██║██║ ╚████║██║  ██║{Fore.CYAN}      ║
║ {Fore.GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝{Fore.CYAN}      ║
║                                                           ║
║ {Fore.YELLOW}Network Traffic Analyzer{Fore.CYAN}     ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def show_capture_info(self, interface, bpf_filter, count, timeout):
        """
        Display capture information
        
        Args:
            interface (str): Network interface used
            bpf_filter (str): BPF filter used
            count (int): Number of packets to capture
            timeout (int): Timeout in seconds
        """
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Capture Information:{Fore.CYAN}                                        ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠═══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Interface: {Fore.GREEN}{interface}{Fore.CYAN}                                           ║{Style.RESET_ALL}")
        
        if bpf_filter:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Filter: {Fore.GREEN}{bpf_filter}{Fore.CYAN}                                              ║{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Filter: {Fore.GREEN}None{Fore.CYAN}                                                ║{Style.RESET_ALL}")
        
        if count > 0:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Packet count: {Fore.GREEN}{count}{Fore.CYAN}                                         ║{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Packet count: {Fore.GREEN}Unlimited{Fore.CYAN}                                     ║{Style.RESET_ALL}")
        
        if timeout > 0:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Timeout: {Fore.GREEN}{timeout} seconds{Fore.CYAN}                                     ║{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Timeout: {Fore.GREEN}Unlimited{Fore.CYAN}                                         ║{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print()
    
    def show_packet(self, packet_info, packet_number):
        """
        Display packet information
        
        Args:
            packet_info (dict): Packet information
            packet_number (int): Packet number
        """
        timestamp = time.strftime("%H:%M:%S", time.localtime(packet_info['timestamp']))
        
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Packet #{packet_number} - {timestamp} - {packet_info['length']} bytes{Fore.CYAN}                        ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠═══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        for layer in packet_info['layers']:
            protocol = layer['protocol']
            color = self.protocol_colors.get(protocol, Fore.WHITE)
            
            print(f"{Fore.CYAN}║ {color}{protocol}{Style.RESET_ALL}")
            
            for key, value in layer.items():
                if key != 'protocol':
                    print(f"{Fore.CYAN}║   {Fore.WHITE}{key}: {Fore.YELLOW}{value}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print()
    
    def show_summary(self, packet_count, duration):
        """
        Display a summary of the capture
        
        Args:
            packet_count (int): Number of packets captured
            duration (float): Duration of the capture in seconds
        """
        packets_per_second = packet_count / duration if duration > 0 else 0
        
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Capture Summary:{Fore.CYAN}                                            ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠═══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Packets captured: {Fore.GREEN}{packet_count}{Fore.CYAN}                                     ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Duration: {Fore.GREEN}{duration:.2f} seconds{Fore.CYAN}                                   ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Rate: {Fore.GREEN}{packets_per_second:.2f} packets/second{Fore.CYAN}                        ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    def show_statistics(self, stats):
        """
        Display capture statistics
        
        Args:
        stats (dict): Capture statistics
        """
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Statistics:{Fore.CYAN}                                                  ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠═══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}║ {Fore.WHITE}Protocols:{Fore.CYAN}                                                   ║{Style.RESET_ALL}")
        protocols_data = []
        for protocol, count in stats['protocols'].items():
            percentage = (count / stats['total']) * 100 if stats['total'] > 0 else 0
            protocols_data.append([protocol, count, f"{percentage:.2f}%"])
        
        protocols_table = tabulate(
            protocols_data, 
            headers=["Protocol", "Count", "Percentage"],
            tablefmt="plain"
        )
        
        for line in protocols_table.split('\n'):
            print(f"{Fore.CYAN}║   {Fore.WHITE}{line}{Fore.CYAN}                                            ║{Style.RESET_ALL}")
        
        if stats['ip_src']:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Top 5 source IP addresses:{Fore.CYAN}                                ║{Style.RESET_ALL}")
            ip_src_data = sorted(stats['ip_src'].items(), key=lambda x: x[1], reverse=True)[:5]
            ip_src_table = tabulate(
                ip_src_data, 
                headers=["IP Address", "Count"],
                tablefmt="plain"
            )
            
            for line in ip_src_table.split('\n'):
                print(f"{Fore.CYAN}║   {Fore.WHITE}{line}{Fore.CYAN}                                            ║{Style.RESET_ALL}")
        
        if stats['ip_dst']:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Top 5 destination IP addresses:{Fore.CYAN}                            ║{Style.RESET_ALL}")
            ip_dst_data = sorted(stats['ip_dst'].items(), key=lambda x: x[1], reverse=True)[:5]
            ip_dst_table = tabulate(
                ip_dst_data, 
                headers=["IP Address", "Count"],
                tablefmt="plain"
            )
            
            for line in ip_dst_table.split('\n'):
                print(f"{Fore.CYAN}║   {Fore.WHITE}{line}{Fore.CYAN}                                            ║{Style.RESET_ALL}")
        
        if stats['ports']:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Top 5 ports:{Fore.CYAN}                                               ║{Style.RESET_ALL}")
            ports_data = sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:5]
            ports_table = tabulate(
                ports_data, 
                headers=["Port", "Count"],
                tablefmt="plain"
            )
            
            for line in ports_table.split('\n'):
                print(f"{Fore.CYAN}║   {Fore.WHITE}{line}{Fore.CYAN}                                            ║{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")