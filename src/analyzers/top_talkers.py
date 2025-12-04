"""
Analyseur Top Talkers
Identifie les hôtes et conversations générant le plus de trafic
"""

from scapy.all import IP, TCP, UDP
from collections import defaultdict
from typing import Dict, Any

class TopTalkersAnalyzer:
    """Analyse les volumes de trafic par IP et protocole"""

    def __init__(self):
        # Key: IP address
        self.ip_stats = defaultdict(lambda: {
            'bytes_sent': 0, 
            'packets_sent': 0, 
            'bytes_received': 0, 
            'packets_received': 0
        })
        
        # Key: Protocol name (TCP, UDP, ICMP, Other)
        self.protocol_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        
        # Key: String "src_ip -> dst_ip"
        self.conversations = defaultdict(lambda: {
            'bytes': 0, 
            'packets': 0,
            'protocol': 'Other',
            'src_port': None,
            'dst_port': None
        })

    def process_packet(self, packet, packet_num: int):
        """Traite un paquet pour les statistiques de volume"""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        length = len(packet)
        
        # IP Stats
        self.ip_stats[src_ip]['bytes_sent'] += length
        self.ip_stats[src_ip]['packets_sent'] += 1
        self.ip_stats[dst_ip]['bytes_received'] += length
        self.ip_stats[dst_ip]['packets_received'] += 1
        
        # Protocol detection
        proto = 'Other'
        src_port = None
        dst_port = None
        
        if packet.haslayer(TCP):
            proto = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ip.proto == 1: # ICMP
            proto = 'ICMP'
            
        # Protocol Stats
        self.protocol_stats[proto]['bytes'] += length
        self.protocol_stats[proto]['packets'] += 1
        
        # Conversation Stats
        # On utilise une clé simple directionnelle pour l'instant
        conv_key = f"{src_ip} -> {dst_ip}"
        conv = self.conversations[conv_key]
        conv['bytes'] += length
        conv['packets'] += 1
        conv['protocol'] = proto
        if src_port: conv['src_port'] = src_port
        if dst_port: conv['dst_port'] = dst_port

    def get_results(self) -> Dict[str, Any]:
        """Retourne les résultats de l'analyse"""
        
        # Top IPs by total volume (sent + received)
        sorted_ips = []
        for ip, stats in self.ip_stats.items():
            total_bytes = stats['bytes_sent'] + stats['bytes_received']
            sorted_ips.append({
                'ip': ip,
                'total_bytes': total_bytes,
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'packets_sent': stats['packets_sent'],
                'packets_received': stats['packets_received']
            })
        
        # Sort by total bytes descending
        sorted_ips.sort(key=lambda x: x['total_bytes'], reverse=True)
        
        # Top Conversations
        sorted_conversations = []
        for conv_key, stats in self.conversations.items():
            # Parse IPs from key for cleaner display if needed
            src, dst = conv_key.split(' -> ')
            
            sorted_conversations.append({
                'conversation': conv_key,
                'src_ip': src,
                'dst_ip': dst,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'protocol': stats['protocol'],
                'src_port': stats['src_port'],
                'dst_port': stats['dst_port']
            })
            
        sorted_conversations.sort(key=lambda x: x['bytes'], reverse=True)
        
        return {
            'top_ips': sorted_ips[:20],  # Top 20 IPs
            'top_conversations': sorted_conversations[:20],  # Top 20 conversations
            'protocol_stats': dict(self.protocol_stats)
        }
