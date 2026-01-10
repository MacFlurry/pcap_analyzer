# Plan: Retransmission Timing Validation

## Phase 1: Setup & Infrastructure [x]

- [x] Créer branche de test `test/retransmission-timing-validation`
- [x] Créer script de génération PCAP sur Raspberry Pi
- [x] Vérifier connectivité SSH vers Raspberry Pi

## Phase 2: TDD - Tests de Validation [x]

- [x] Écrire test unitaire: valider parsing des retransmissions SYN
- [x] Écrire test unitaire: valider parsing des retransmissions PSH,ACK
- [x] Écrire test d'intégration: cohérence CLI vs rapport HTML
- [x] Confirmer les tests échouent (Red phase) - BUG CONFIRMÉ: delay=None dans tshark backend

## Phase 3: Génération PCAP - SYN Retransmissions [x]

- [x] Créer script Python pour simuler SYN floods avec délais contrôlés
- [x] Générer trafic: 3 SYN retrans sur ~3 secondes (1s, 2s intervalles)
- [x] Validé avec tshark (ground truth): delays 1.0s, 2.0s, 3.0s ✅

## Phase 4: Génération PCAP - PSH,ACK Retransmissions [x]

- [x] Créer script pour simuler retransmissions data (PSH,ACK)
- [x] Générer trafic: 3 PSH,ACK retrans à 0.2s, 0.4s, 0.8s
- [x] Validé avec tshark: delays 0.2s, 0.4s, 0.8s ✅

## Phase 5: Validation CLI [x]

- [x] Analyser PCAP avec `pcap_analyzer analyze`
- [x] BUG TROUVÉ: tshark backend retournait delay=None
- [x] FIX: Ajout de _get_all_tcp_packets() pour indexer les paquets originaux
- [x] Délais maintenant correctement calculés ✅

## Phase 6: Validation Rapport HTML [x]

- [x] Générer rapport HTML avec `--export-html`
- [x] HTML affiche Avg Delay: 2000.0ms (SYN) et 476.7ms (PSH,ACK) ✅
- [x] Cohérence CLI/HTML confirmée ✅

## Phase 7: Documentation & Commit [x] [30ec2e2]

- [x] Bug identifié et corrigé: retransmission_tshark.py delay calculation
- [x] Tests TDD créés: test_retransmission_timing_validation.py
- [x] Script de génération: generate_retransmission_pcap.py
- [x] Commit final avec structured message: 30ec2e2
