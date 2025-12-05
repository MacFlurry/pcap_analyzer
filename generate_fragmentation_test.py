#!/usr/bin/env python3
"""
Génère un fichier PCAP avec fragmentation IP pour tester l'analyseur
"""

from scapy.all import IP, ICMP, Raw, wrpcap
import random

# Liste des paquets à générer
packets = []

# Cas 1: Fragmentation normale avec réassemblage complet
# Un gros paquet ICMP fragmenté en 3 morceaux
large_payload = b"A" * 3000  # 3000 bytes de données

# Fragment 1 (offset 0, MF=1)
frag1 = IP(src="192.168.1.100", dst="10.0.0.1", id=12345, flags="MF", frag=0) / Raw(load=large_payload[:1480])
packets.append(frag1)

# Fragment 2 (offset 185, MF=1) - offset en unités de 8 bytes: 1480/8 = 185
frag2 = IP(src="192.168.1.100", dst="10.0.0.1", id=12345, flags="MF", frag=185) / Raw(load=large_payload[1480:2960])
packets.append(frag2)

# Fragment 3 (offset 370, MF=0) - dernier fragment: 2960/8 = 370
frag3 = IP(src="192.168.1.100", dst="10.0.0.1", id=12345, flags=0, frag=370) / Raw(load=large_payload[2960:])
packets.append(frag3)

# Cas 2: Fragmentation avec fragment manquant (incomplet)
# Fragment 1 d'un groupe qui ne sera jamais complet
incomplete_payload = b"B" * 2000
frag_inc1 = IP(src="192.168.1.101", dst="10.0.0.2", id=54321, flags="MF", frag=0) / Raw(load=incomplete_payload[:1480])
packets.append(frag_inc1)
# Le fragment 2 est volontairement manquant pour simuler une perte

# Cas 3: Multiple fragmentations du même flux
for i in range(5):
    payload = f"Packet{i}".encode() * 400  # ~2800 bytes
    
    # Fragment 1
    f1 = IP(src="192.168.1.102", dst="10.0.0.3", id=60000+i, flags="MF", frag=0) / Raw(load=payload[:1480])
    packets.append(f1)
    
    # Fragment 2 (dernier)
    f2 = IP(src="192.168.1.102", dst="10.0.0.3", id=60000+i, flags=0, frag=185) / Raw(load=payload[1480:])
    packets.append(f2)

# Cas 4: Paquets non fragmentés pour contraste
for i in range(10):
    normal_pkt = IP(src="192.168.1.200", dst="10.0.0.4") / ICMP() / Raw(load=b"X" * 100)
    packets.append(normal_pkt)

# Cas 5: Paquets avec DF flag (Don't Fragment)
for i in range(5):
    df_pkt = IP(src="192.168.1.201", dst="10.0.0.5", flags="DF") / ICMP() / Raw(load=b"Y" * 200)
    packets.append(df_pkt)

# Mélanger les paquets pour simuler un trafic réaliste
random.shuffle(packets)

# Écrire le fichier PCAP
output_file = "test_fragmentation.pcap"
wrpcap(output_file, packets)

print(f"✓ Fichier {output_file} créé avec succès")
print(f"  - Total paquets: {len(packets)}")
print(f"  - Fragments complets: 13 (1 groupe de 3 + 5 groupes de 2)")
print(f"  - Fragments incomplets: 1 (groupe avec fragment manquant)")
print(f"  - Paquets normaux: 10")
print(f"  - Paquets avec DF: 5")
