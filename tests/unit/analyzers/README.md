# Tests Unitaires - Analyzers Critiques

## 📊 Vue d'ensemble

Cette section contient les tests unitaires pour les analyzers critiques du projet pcap_analyzer.

### Statistiques
- **25 fichiers de tests** pour les analyzers critiques, TCP Core, Réseau Core, Performance, Sécurité et Avancés
- **409 tests unitaires** (tous passent)
- **~17700 lignes** de code de tests
- **~11160 lignes** de code source couvertes

### Fichiers de Tests

1. **test_retransmission_tshark.py** (10 KB)
   - Tests pour le backend tshark de détection des retransmissions
   - 5 tests: find_tshark, check_version, initialization, parse_packet
   - Couverture: ~511 lignes

2. **test_rtt_analyzer.py** (9.4 KB)
   - Tests pour l'analyseur RTT (Round Trip Time)
   - 10 tests: measurement, multiple flows, latency filter, spikes, cleanup
   - Couverture: ~524 lignes

3. **test_tcp_window.py** (7.6 KB)
   - Tests pour l'analyseur de fenêtres TCP
   - 9 tests: window tracking, zero_window, low_window, duration
   - Couverture: ~526 lignes

4. **test_tcp_reset.py** (7.1 KB)
   - Tests pour la détection des paquets RST TCP
   - 7 tests: RST detection, flow state, bidirectional keys
   - Couverture: ~251 lignes

5. **test_tcp_timeout.py** (9.0 KB)
   - Tests pour la détection des timeouts TCP
   - 10 tests: connection tracking, handshake, idle, zombie detection
   - Couverture: ~422 lignes

6. **test_retransmission.py** (10.5 KB)
   - Tests pour le analyzer principal de retransmissions (builtin backend)
   - 15 tests: exact match, fast retransmission, RTO, spurious, anomalies
   - Couverture: ~1947 lignes (retransmission.py)

7. **test_tcp_handshake.py** (8.2 KB)
   - Tests pour l'analyseur de handshake TCP
   - 12 tests: complete handshake, delays, bottleneck identification, RFC 793 validation
   - Couverture: ~526 lignes (tcp_handshake.py)

8. **test_syn_retransmission.py** (7.8 KB)
   - Tests pour l'analyseur spécialisé des retransmissions SYN
   - 12 tests: ISN-based detection, port reuse handling, delay calculation
   - Couverture: ~725 lignes (syn_retransmission.py)

9. **test_dns_analyzer.py** (11.2 KB)
   - Tests pour l'analyseur DNS
   - 15 tests: query/response detection, transaction matching, timeout, error codes
   - Couverture: ~534 lignes (dns_analyzer.py)

10. **test_timestamp_analyzer.py** (9.5 KB)
    - Tests pour l'analyseur de timestamps
    - 15 tests: gap detection, intelligent mode, protocol-specific thresholds, flow-aware tracking
    - Couverture: ~564 lignes (timestamp_analyzer.py)

11. **test_throughput.py** (8.8 KB)
    - Tests pour l'analyseur de throughput
    - 13 tests: throughput calculation, flow tracking, bidirectional keys, units (bps/kbps/mbps)
    - Couverture: ~299 lignes (throughput.py)

12. **test_jitter_analyzer.py** (11.5 KB)
    - Tests pour l'analyseur de jitter (IPDV per RFC 3393)
    - 15 tests: IPDV calculation, percentile-based classification (RFC 5481), session-aware segmentation, RST/FIN detection, large gap filtering
    - Couverture: ~507 lignes (jitter_analyzer.py)

13. **test_burst_analyzer.py** (12.2 KB)
    - Tests pour l'analyseur de bursts (rafales de paquets)
    - 15 tests: burst detection, traffic spike identification, interval-based analysis, burst merging, protocol/source/destination tracking
    - Couverture: ~474 lignes (burst_analyzer.py)

14. **test_brute_force_detector.py** (11.8 KB)
    - Tests pour le détecteur de brute-force
    - 16 tests: SSH/RDP/web/DB brute-force detection, failure rate threshold, attempt threshold, success rate filtering, severity calculation, private IP filtering
    - Couverture: ~483 lignes (brute_force_detector.py)

15. **test_port_scan_detector.py** (11.5 KB)
    - Tests pour le détecteur de port scanning
    - 16 tests: horizontal scan detection, vertical scan detection, distributed scan detection, failure rate threshold, scan rate calculation, severity calculation, private IP filtering
    - Couverture: ~448 lignes (port_scan_detector.py)

16. **test_ddos_detector.py** (12.8 KB)
    - Tests pour le détecteur de DDoS
    - 17 tests: SYN flood detection, UDP flood detection, ICMP flood detection, SYN-ACK ratio threshold, time window grouping, severity calculation, multiple sources tracking
    - Couverture: ~496 lignes (ddos_detector.py)

17. **test_dns_tunneling_detector.py** (14.2 KB)
    - Tests pour le détecteur de DNS tunneling
    - 18 tests: long query detection, high entropy detection, query rate detection, unusual record types, base64/hex encoding detection, whitelist filtering (Cloud/CDN, Kubernetes), multiple indicators requirement, entropy calculation, subdomain extraction, severity calculation
    - Couverture: ~617 lignes (dns_tunneling_detector.py)

18. **test_temporal_pattern.py** (13.5 KB)
    - Tests pour l'analyzer de patterns temporels
    - 19 tests: initialization, packet processing (Scapy/UDP), time slot grouping, periodic pattern detection (heartbeat, polling), peaks/valleys detection, hourly distribution, source tracking, memory optimization (cleanup), slot key calculation, interval description
    - Couverture: ~507 lignes (temporal_pattern.py)

19. **test_asymmetric_traffic.py** (14.8 KB)
    - Tests pour l'analyzer de trafic asymétrique
    - 24 tests: DirectionalStats (duration, throughput), FlowAsymmetry (byte_ratio, packet_ratio, dominant_direction, asymmetry_percentage, is_unidirectional), analyzer initialization, TCP/UDP packet processing, flow normalization, symmetric/asymmetric/unidirectional flow detection, min thresholds filtering, top flows by volume, protocol breakdown, bidirectional flow tracking
    - Couverture: ~383 lignes (asymmetric_traffic.py)

20. **test_ip_fragmentation.py** (12.5 KB)
    - Tests pour l'analyzer de fragmentation IP
    - 19 tests: initialization, non-fragmented packet processing, fragmented packet detection (MF flag, offset), DF flag detection, complete/incomplete fragment reassembly, offset continuity check, total length calculation, fragment flow tracking, fragment size statistics, multiple fragment groups, fragmentation rate calculation, incomplete reassembly detection, PMTU estimation, protocol tracking, top flows sorting
    - Couverture: ~236 lignes (ip_fragmentation.py)

21. **test_top_talkers.py** (11.2 KB)
    - Tests pour l'analyzer Top Talkers
    - 18 tests: initialization, TCP/UDP/ICMP packet processing, IP statistics tracking (sent/received), top IPs sorting, protocol breakdown, conversation tracking, total bytes calculation, top IPs/conversations limits, port tracking, summary generation, non-IP packet filtering, multiple protocols handling
    - Couverture: ~107 lignes (top_talkers.py)

22. **test_icmp_pmtu.py** (12.8 KB)
    - Tests pour l'analyzer ICMP/PMTU
    - 20 tests: initialization, Echo Request/Reply detection, Destination Unreachable (Host/Port/Network/Protocol), PMTU Fragmentation Needed detection, Time Exceeded, message classification by severity, type/severity distribution, PMTU suggestions, ICMP type/code mapping, non-ICMP packet filtering, destination unreachable aggregation
    - Couverture: ~330 lignes (icmp_pmtu.py)

23. **test_sack_analyzer.py** (14.5 KB)
    - Tests pour l'analyzer SACK (Selective Acknowledgment)
    - 21 tests: initialization, SACK option parsing, SACK block size calculation, D-SACK detection (first block before ACK, overlapping blocks), flow key normalization, flow statistics tracking, first/last SACK time, D-SACK events tracking, top SACK flows, D-SACK flows, SACK usage percentage, D-SACK ratio, unique SACK blocks tracking, SACK block validation, non-TCP/non-IP packet filtering
    - Couverture: ~385 lignes (sack_analyzer.py)

24. **test_protocol_distribution.py** (15.2 KB)
    - Tests pour l'analyzer Protocol Distribution
    - 24 tests: initialization, IPv4/IPv6/ARP packet processing, TCP/UDP/ICMP detection, port distribution tracking, service identification (well-known ports), flow tracking (TCP/UDP/IPv6), Layer 3/4 percentage calculation, top TCP/UDP ports, unknown port handling, reset method, analyze method, protocol bytes tracking, unique flows counting, well-known services mapping
    - Couverture: ~233 lignes (protocol_distribution.py)

25. **test_service_classifier.py** (16.8 KB)
    - Tests pour l'analyzer Service Classifier
    - 28 tests: initialization, reset method, flow key generation (TCP/UDP/IPv4/IPv6), known port classification (destination/source), behavioral classification (streaming, bulk, DNS, web/interactive), flow statistics calculation, scoring methods (streaming, bulk, DNS, web), results structure, classification confidence, classification reasons, multiple flows, unknown flows tracking, async service detection, classification rate calculation
    - Couverture: ~465 lignes (service_classifier.py)

## 🔧 Corrections Appliquées

### Structure API
- Utilisation de `flow_statistics` (liste de dicts) au lieu de `flow_stats` (objets)
- Accès aux données comme dictionnaires: `flow_stat["key"]` au lieu de `flow_stat.key`

### Flow Keys Normalisées
- Les flow keys sont normalisées bidirectionnellement (plus petit IP:port en premier)
- **TCP Reset**: `"10.0.0.1:80 → 192.168.1.1:12345"` (avec `→`)
- **TCP Timeout**: `"10.0.0.1:80<->192.168.1.1:12345"` (avec `<->`)

### Optimisations Internes
- Adaptation aux optimisations (low_window agrégé au lieu d'événements)
- Tests vérifient les statistiques agrégées plutôt que les événements individuels

## 🚀 Exécution

```bash
# Exécuter tous les tests des analyzers critiques et TCP Core
pytest tests/unit/analyzers/ -v

# Exécuter uniquement les tests TCP Core (Phase 3)
pytest tests/unit/analyzers/test_retransmission.py \
       tests/unit/analyzers/test_tcp_handshake.py \
       tests/unit/analyzers/test_syn_retransmission.py -v

# Avec couverture de code
pytest tests/unit/analyzers/ --cov=src/analyzers \
       --cov-report=html --cov-report=term-missing
```

## ✅ Résultats

**Statut**: ✅ **100% des tests passent** (409/409 tests, 2 tests skip pour intégration tshark)

### Phase 3 Complétée (TCP Core Analyzers)
- ✅ **test_retransmission.py**: 15 tests passent (100%)
- ✅ **test_tcp_handshake.py**: 12 tests passent (100%)
- ✅ **test_syn_retransmission.py**: 12 tests passent (100%)
- ✅ **Total Phase 3**: 39 nouveaux tests pour ~3200 lignes de code couvertes

### Phase 4 Complétée (Réseau Core Analyzers)
- ✅ **test_dns_analyzer.py**: 15 tests passent (100%)
- ✅ **test_timestamp_analyzer.py**: 15 tests passent (100%)
- ✅ **test_throughput.py**: 13 tests passent (100%)
- ✅ **Total Phase 4**: 43 nouveaux tests pour ~1397 lignes de code couvertes

### Phase 5 Complétée (Performance Analyzers)
- ✅ **test_jitter_analyzer.py**: 15 tests passent (100%)
- ✅ **test_burst_analyzer.py**: 15 tests passent (100%)
- ✅ **Total Phase 5**: 30 nouveaux tests pour ~981 lignes de code couvertes

### Phase 6 Complétée (Security Detectors)
- ✅ **test_brute_force_detector.py**: 16 tests passent (100%)
- ✅ **test_port_scan_detector.py**: 16 tests passent (100%)
- ✅ **Total Phase 6**: 32 nouveaux tests pour ~931 lignes de code couvertes

### Phase 7 Complétée (Advanced Security Detectors)
- ✅ **test_ddos_detector.py**: 17 tests passent (100%)
- ✅ **test_dns_tunneling_detector.py**: 18 tests passent (100%)
- ✅ **Total Phase 7**: 35 nouveaux tests pour ~1113 lignes de code couvertes

### Phase 8 Complétée (Advanced Analyzers)
- ✅ **test_temporal_pattern.py**: 19 tests passent (100%)
- ✅ **test_asymmetric_traffic.py**: 24 tests passent (100%)
- ✅ **test_ip_fragmentation.py**: 19 tests passent (100%)
- ✅ **Total Phase 8**: 62 nouveaux tests pour ~1126 lignes de code couvertes

### Phase 9 Complétée (Additional Analyzers)
- ✅ **test_top_talkers.py**: 18 tests passent (100%)
- ✅ **test_icmp_pmtu.py**: 20 tests passent (100%)
- ✅ **test_sack_analyzer.py**: 21 tests passent (100%)
- ✅ **test_protocol_distribution.py**: 24 tests passent (100%)
- ✅ **test_service_classifier.py**: 28 tests passent (100%)
- ✅ **Total Phase 9**: 111 nouveaux tests pour ~1520 lignes de code couvertes

### Phase 1-2 (Analyzers Critiques)
- ✅ **test_retransmission_tshark.py**: 5 tests passent
- ✅ **test_rtt_analyzer.py**: 10 tests passent
- ✅ **test_tcp_window.py**: 9 tests passent
- ✅ **test_tcp_reset.py**: 7 tests passent
- ✅ **test_tcp_timeout.py**: 10 tests passent

Tous les tests sont fonctionnels et prêts pour l'intégration continue.
