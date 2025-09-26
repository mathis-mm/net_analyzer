#!/usr/bin/env python3

import argparse
import sys
import time
from colorama import init, Fore, Style

from capture.packet_capture import PacketCapture
from analyzer.packet_analyzer import PacketAnalyzer
from cli.display import Display
from utils.helpers import get_available_interfaces, validate_filter


init()

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer - Network packet capture and analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("-i", "--interface", 
                        help="Network interface to use for capture")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter for capture (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="Maximum capture duration in seconds (0 = unlimited)")
    parser.add_argument("-o", "--output", 
                        help="Output file to save captured packets")
    parser.add_argument("-l", "--live", action="store_true",
                        help="Display packets in real-time during capture")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="Display list of available network interfaces")
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print(f"{Fore.GREEN}Available network interfaces:{Style.RESET_ALL}")
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {Fore.CYAN}{iface}{Style.RESET_ALL}")
        return 0
    
    if not args.interface:
        print(f"{Fore.RED}Error: No interface specified. Use -i or --interface.{Style.RESET_ALL}")
        print(f"Use {Fore.YELLOW}--list-interfaces{Style.RESET_ALL} to see available interfaces.")
        return 1
    
    if args.filter and not validate_filter(args.filter):
        print(f"{Fore.RED}Error: Invalid BPF filter: {args.filter}{Style.RESET_ALL}")
        return 1
    
    try:
        display = Display()
        packet_capture = PacketCapture(args.interface, args.filter)
        packet_analyzer = PacketAnalyzer()
        
        display.show_banner()
        display.show_capture_info(args.interface, args.filter, args.count, args.timeout)
        
        print(f"{Fore.GREEN}Starting capture..{Style.RESET_ALL}")
        print(f"Press {Fore.YELLOW}Ctrl+C{Style.RESET_ALL} stop capture")
        
        start_time = time.time()
        packet_count = 0
        
        while True:
            if args.count > 0 and packet_count >= args.count:
                break
                
            if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                break
                
            packet = packet_capture.capture_packet()
            if packet:
                packet_count += 1
                
                analyzed_packet = packet_analyzer.analyze(packet)
                
                if args.live:
                    display.show_packet(analyzed_packet, packet_count)
                
                if args.output:
                    packet_capture.save_packet(packet, args.output)
        
        display.show_summary(packet_count, time.time() - start_time)
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Capture interrupted by user{Style.RESET_ALL}")
        return 0
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    sys.exit(main())