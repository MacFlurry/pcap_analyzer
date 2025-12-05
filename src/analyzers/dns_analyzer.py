"""
Analyseur de résolutions DNS
"""

from scapy.all import Packet, DNS, DNSQR, DNSRR, UDP, IP
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class DNSQuery:
    """Requête DNS"""
    packet_num: int
    timestamp: float
    query_id: int
    query_name: str
    query_type: str
    src_ip: str
    dst_ip: str
    src_port: int


@dataclass
class DNSResponse:
    """Réponse DNS"""
    packet_num: int
    timestamp: float
    query_id: int
    query_name: str
    response_code: int
    response_code_name: str
    answers: List[str]
    src_ip: str
    dst_ip: str


@dataclass
class DNSTransaction:
    """Transaction DNS complète (query + response)"""
    query: DNSQuery
    response: Optional[DNSResponse]
    response_time: Optional[float]  # Temps de réponse en secondes
    timed_out: bool
    repeated: bool  # Requête répétée (même domaine/type dans un court délai)
    status: str  # 'success', 'timeout', 'error'


class DNSAnalyzer:
    """Analyseur de résolutions DNS"""

    DNS_TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        255: 'ANY'
    }

    DNS_RCODES = {
        0: 'NOERROR',
        1: 'FORMERR',
        2: 'SERVFAIL',
        3: 'NXDOMAIN',
        4: 'NOTIMP',
        5: 'REFUSED'
    }

    def __init__(self, response_warning: float = 0.1, response_critical: float = 1.0,
                 timeout: float = 5.0, latency_filter: Optional[float] = None):
        """
        Initialise l'analyseur DNS

        Args:
            response_warning: Seuil d'alerte temps de réponse (secondes)
            response_critical: Seuil critique temps de réponse (secondes)
            timeout: Délai de timeout pour considérer une requête perdue (secondes)
            latency_filter: Si défini, ne garde que les transactions avec temps >= ce seuil
        """
        self.response_warning = response_warning
        self.response_critical = response_critical
        self.timeout = timeout
        self.latency_filter = latency_filter

        self.queries: List[DNSQuery] = []
        self.responses: List[DNSResponse] = []
        self.transactions: List[DNSTransaction] = []

        # Tracking interne: {query_id: DNSQuery}
        self._pending_queries: Dict[int, DNSQuery] = {}

        # Pour détecter les requêtes répétées: {(query_name, query_type): timestamp}
        self._recent_queries: Dict[tuple, float] = {}

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les transactions DNS

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Traite un paquet individuel"""
        if not packet.haslayer(DNS):
            return

        # Vérifie si le paquet contient une couche UDP (DNS par défaut utilise UDP)
        # Certains DNS peuvent utiliser TCP, mais l'analyseur se concentre sur UDP pour l'instant
        if not packet.haslayer(UDP):
            return # Ignore les paquets DNS qui ne sont pas sur UDP
        
        dns = packet[DNS]
        
        # Requête DNS (qr=0)
        if dns.qr == 0:
            self._process_query(packet_num, packet, dns)

        # Réponse DNS (qr=1)
        elif dns.qr == 1:
            self._process_response(packet_num, packet, dns)

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Les requêtes sans réponse sont déjà gérées dans process_packet
        # Pas besoin de check_timeouts supplémentaire
        return self._generate_report()

    def _process_query(self, packet_num: int, packet: Packet, dns: DNS) -> None:
        """Traite une requête DNS"""
        if not dns.qd:  # Pas de question
            return

        timestamp = float(packet.time)
        ip = packet[IP]
        udp = packet[UDP]

        query_name = dns.qd.qname.decode('utf-8') if isinstance(dns.qd.qname, bytes) else dns.qd.qname
        query_type = self.DNS_TYPES.get(dns.qd.qtype, f'TYPE{dns.qd.qtype}')

        query = DNSQuery(
            packet_num=packet_num,
            timestamp=timestamp,
            query_id=dns.id,
            query_name=query_name,
            query_type=query_type,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=udp.sport
        )

        self.queries.append(query)

        # Détecte les requêtes répétées
        query_key = (query_name, query_type)
        is_repeated = False

        if query_key in self._recent_queries:
            last_time = self._recent_queries[query_key]
            if timestamp - last_time < 2.0:  # Répétée dans les 2 secondes
                is_repeated = True

        self._recent_queries[query_key] = timestamp

        # Enregistre la query en attente de réponse
        # Note: On utilise (id, src_ip, src_port) comme clé pour gérer les collisions d'ID
        query_full_key = (dns.id, ip.src, udp.sport)
        self._pending_queries[query_full_key] = query

        # Si c'est une requête répétée et qu'il n'y a pas de réponse en attente,
        # on peut supposer un timeout de la requête précédente
        if is_repeated:
            # Marque dans les métadonnées
            query.repeated = is_repeated

    def _process_response(self, packet_num: int, packet: Packet, dns: DNS) -> None:
        """Traite une réponse DNS"""
        timestamp = float(packet.time)
        ip = packet[IP]

        # Extrait le nom de domaine de la question
        query_name = ""
        if dns.qd:
            query_name = dns.qd.qname.decode('utf-8') if isinstance(dns.qd.qname, bytes) else dns.qd.qname

        # Extrait les réponses
        answers = []
        if dns.an:
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if hasattr(rr, 'rdata'):
                        rdata = str(rr.rdata)
                        answers.append(rdata)
                except:
                    pass

        rcode_name = self.DNS_RCODES.get(dns.rcode, f'RCODE{dns.rcode}')

        response = DNSResponse(
            packet_num=packet_num,
            timestamp=timestamp,
            query_id=dns.id,
            query_name=query_name,
            response_code=dns.rcode,
            response_code_name=rcode_name,
            answers=answers,
            src_ip=ip.src,
            dst_ip=ip.dst
        )

        self.responses.append(response)

        # Cherche la requête correspondante
        # La réponse vient du serveur DNS (dst de la query), donc on cherche
        # une query avec dst_ip = response.src_ip
        query_full_key = None
        matching_query = None

        for key, query in list(self._pending_queries.items()):
            query_id, query_src_ip, query_src_port = key
            if query_id == dns.id and query.dst_ip == ip.src:
                matching_query = query
                query_full_key = key
                break

        if matching_query:
            response_time = timestamp - matching_query.timestamp

            # Détermine le statut
            if dns.rcode == 0:  # NOERROR
                if response_time > self.response_critical:
                    status = 'slow'
                else:
                    status = 'success'
            else:
                status = 'error'

            is_repeated = hasattr(matching_query, 'repeated') and matching_query.repeated

            # Applique le filtre de latence si défini
            if self.latency_filter is None or response_time >= self.latency_filter:
                transaction = DNSTransaction(
                    query=matching_query,
                    response=response,
                    response_time=response_time,
                    timed_out=False,
                    repeated=is_repeated,
                    status=status
                )

                self.transactions.append(transaction)

            # Retire la query des pending
            if query_full_key:
                del self._pending_queries[query_full_key]

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse DNS"""
        total_queries = len(self.queries)
        total_responses = len(self.responses)
        total_transactions = len(self.transactions)

        # Transactions avec réponse
        successful = [t for t in self.transactions if t.status == 'success']
        slow = [t for t in self.transactions if t.status == 'slow']
        errors = [t for t in self.transactions if t.status == 'error']
        timeouts = [t for t in self.transactions if t.timed_out]
        repeated = [t for t in self.transactions if t.repeated]

        # Response times
        response_times = [t.response_time for t in self.transactions if t.response_time is not None]

        stats = {}
        if response_times:
            stats = {
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'mean_response_time': sum(response_times) / len(response_times),
            }

        # Domaines problématiques
        problematic_domains = defaultdict(int)
        for t in self.transactions:
            if t.status in ['slow', 'error', 'timeout']:
                problematic_domains[t.query.query_name] += 1

        # Top domaines problématiques
        top_problematic = sorted(
            problematic_domains.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'total_queries': total_queries,
            'total_responses': total_responses,
            'total_transactions': total_transactions,
            'successful_transactions': len(successful),
            'slow_transactions': len(slow),
            'error_transactions': len(errors),
            'timeout_transactions': len(timeouts),
            'repeated_queries': len(repeated),
            'response_time_statistics': stats,
            'thresholds': {
                'warning_seconds': self.response_warning,
                'critical_seconds': self.response_critical,
                'timeout_seconds': self.timeout
            },
            'problematic_domains': dict(problematic_domains),
            'top_problematic_domains': top_problematic,
            'transactions': [self._transaction_to_dict(t) for t in self.transactions],
            'slow_transactions_details': [self._transaction_to_dict(t) for t in slow],
            'timeout_details': [self._transaction_to_dict(t) for t in timeouts]
        }

    def _transaction_to_dict(self, transaction: DNSTransaction) -> Dict[str, Any]:
        """Convertit une transaction DNS en dictionnaire"""
        return {
            'query': asdict(transaction.query),
            'response': asdict(transaction.response) if transaction.response else None,
            'response_time': transaction.response_time,
            'timed_out': transaction.timed_out,
            'repeated': transaction.repeated,
            'status': transaction.status
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse DNS"""
        if not self.transactions:
            return "📊 Aucune transaction DNS détectée."

        timeouts = [t for t in self.transactions if t.timed_out]
        slow = [t for t in self.transactions if t.status == 'slow']
        errors = [t for t in self.transactions if t.status == 'error']
        repeated = [t for t in self.transactions if t.repeated]

        summary = f"📊 Analyse DNS:\n"
        summary += f"  - Requêtes totales: {len(self.queries)}\n"
        summary += f"  - Transactions complètes: {len(self.transactions)}\n"
        summary += f"  - Timeouts: {len(timeouts)}\n"
        summary += f"  - Réponses lentes: {len(slow)}\n"
        summary += f"  - Erreurs: {len(errors)}\n"
        summary += f"  - Requêtes répétées: {len(repeated)}\n"

        if slow:
            summary += f"\n🔴 {len(slow)} réponse(s) DNS lente(s):\n"

            for t in slow[:10]:
                summary += f"\n  {t.query.query_name} ({t.query.query_type})\n"
                summary += f"    - Temps de réponse: {t.response_time * 1000:.2f}ms\n"
                summary += f"    - Serveur: {t.query.dst_ip}\n"

        if timeouts:
            summary += f"\n⚠️ {len(timeouts)} timeout(s) DNS:\n"

            # Compte par domaine
            timeout_domains = defaultdict(int)
            for t in timeouts:
                timeout_domains[t.query.query_name] += 1

            for domain, count in sorted(timeout_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                summary += f"    - {domain}: {count} timeout(s)\n"

        if errors:
            summary += f"\n❌ {len(errors)} erreur(s) DNS:\n"

            for t in errors[:5]:
                summary += f"    - {t.query.query_name}: {t.response.response_code_name if t.response else 'N/A'}\n"

        if not slow and not timeouts and not errors:
            summary += f"\n✓ Toutes les résolutions DNS sont normales.\n"

        return summary
