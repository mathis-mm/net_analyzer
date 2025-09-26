#!/usr/bin/env python3

import os
import sys
import socket
from scapy.all import get_if_list, conf

def get_available_interfaces():
    try:
        return get_if_list()
    except Exception as e:
        print(f"Erreur lors de la récupération des interfaces: {str(e)}")
        return []

def validate_filter(bpf_filter):
    try:
        if not bpf_filter:
            return True
            
        operators = ['and', 'or', 'not', '&&', '||', '!']
        for op in operators:
            bpf_filter = bpf_filter.replace(op, '')
            
        protocols = ['tcp', 'udp', 'icmp', 'ip', 'arp', 'ether']
        for proto in protocols:
            bpf_filter = bpf_filter.replace(proto, '')
            
        directives = ['port', 'host', 'net', 'src', 'dst', 'portrange']
        for directive in directives:
            bpf_filter = bpf_filter.replace(directive, '')
            
        bpf_filter = bpf_filter.replace(' ', '')
        bpf_filter = bpf_filter.replace('.', '')
        bpf_filter = bpf_filter.replace(':', '')
        bpf_filter = bpf_filter.replace('/', '')
        bpf_filter = bpf_filter.replace('-', '')
        bpf_filter = bpf_filter.replace('_', '')
        bpf_filter = bpf_filter.replace('(', '')
        bpf_filter = bpf_filter.replace(')', '')
        bpf_filter = bpf_filter.replace('[', '')
        bpf_filter = bpf_filter.replace(']', '')
        bpf_filter = bpf_filter.replace('{', '')
        bpf_filter = bpf_filter.replace('}', '')
        bpf_filter = bpf_filter.replace('=', '')
        bpf_filter = bpf_filter.replace('<', '')
        bpf_filter = bpf_filter.replace('>', '')
        
        return bpf_filter.strip() == ''
    except Exception:
        return False

def get_hostname_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip

def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol)
    except (socket.error, OSError):
        return str(port)

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def is_admin():
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0