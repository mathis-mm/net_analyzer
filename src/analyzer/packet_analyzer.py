from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether

class PacketAnalyzer:
    
    def __init__(self):
        self.protocol_handlers = {
            IP: self._analyze_ip,
            TCP: self._analyze_tcp,
            UDP: self._analyze_udp,
            ICMP: self._analyze_icmp,
            ARP: self._analyze_arp,
            Ether: self._analyze_ether
        }
        
        self.stats = {
            'total': 0,
            'protocols': {},
            'ip_src': {},
            'ip_dst': {},
            'ports': {}
        }
    
def analyze(self, packet):
    try:
        result = {
            'timestamp': getattr(packet, "time", None),
            'length': len(packet),
            'layers': [],
            'summary': packet.summary()
        }
        
        self.stats['total'] += 1
        
        for layer in packet.layers():
            if layer in self.protocol_handlers:
                layer_info = self.protocol_handlers[layer](packet.getlayer(layer))
                result['layers'].append(layer_info)
                
            self.stats['protocols'][layer.__name__] += 1
        
        return result
    except Exception as e:
        return {'error': str(e), 'summary': packet.summary()}
    
    def _analyze_ip(self, ip_layer):
        result = {
            'protocol': 'IP',
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'version': ip_layer.version,
            'ttl': ip_layer.ttl,
            'id': ip_layer.id
        }
        
        if ip_layer.src not in self.stats['ip_src']:
            self.stats['ip_src'][ip_layer.src] = 0
        self.stats['ip_src'][ip_layer.src] += 1
        
        if ip_layer.dst not in self.stats['ip_dst']:
            self.stats['ip_dst'][ip_layer.dst] = 0
        self.stats['ip_dst'][ip_layer.dst] += 1
        
        return result
    
    def _analyze_tcp(self, tcp_layer):
        result = {
            'protocol': 'TCP',
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': self._get_tcp_flags(tcp_layer)
        }
        
        for port in [tcp_layer.sport, tcp_layer.dport]:
            port_key = f"TCP:{port}"
            if port_key not in self.stats['ports']:
                self.stats['ports'][port_key] = 0
            self.stats['ports'][port_key] += 1
        
        return result
    
    def _analyze_udp(self, udp_layer):
        result = {
            'protocol': 'UDP',
            'sport': udp_layer.sport,
            'dport': udp_layer.dport,
            'len': udp_layer.len
        }
        
        for port in [udp_layer.sport, udp_layer.dport]:
            port_key = f"UDP:{port}"
            if port_key not in self.stats['ports']:
                self.stats['ports'][port_key] = 0
            self.stats['ports'][port_key] += 1
        
        return result
    
    def _analyze_icmp(self, icmp_layer):
        return {
            'protocol': 'ICMP',
            'type': icmp_layer.type,
            'code': icmp_layer.code
        }
    
    def _analyze_arp(self, arp_layer):
        return {
            'protocol': 'ARP',
            'op': arp_layer.op,
            'hwsrc': arp_layer.hwsrc,
            'hwdst': arp_layer.hwdst,
            'psrc': arp_layer.psrc,
            'pdst': arp_layer.pdst
        }
    
    def _analyze_ether(self, ether_layer):
        return {
            'protocol': 'Ethernet',
            'src': ether_layer.src,
            'dst': ether_layer.dst,
            'type': ether_layer.type
        }
    
    def _get_tcp_flags(self, tcp_layer):
        flags = []
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        if tcp_layer.flags.U:
            flags.append('URG')
        return flags
    
    def get_statistics(self):
        return self.stats
    
    def reset_statistics(self):
        self.stats = {
            'total': 0,
            'protocols': {},
            'ip_src': {},
            'ip_dst': {},
            'ports': {}
        }
