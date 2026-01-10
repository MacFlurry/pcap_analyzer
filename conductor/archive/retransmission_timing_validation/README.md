# Track: Retransmission Timing Validation

## Objective

Valider que les délais de retransmission (SYN et PSH,ACK) sont correctement reportés 
dans le CLI et les rapports HTML. Investigation d'une divergence potentielle entre 
les deux modes d'affichage.

## Context

- **Problème reporté**: Les temps de délais des retransmissions peuvent différer entre 
  le CLI et le rapport HTML
- **Scope**: Retransmissions SYN (handshake) et PSH,ACK (data transfer)
- **Environnement de test**: Raspberry Pi (192.168.25.15) pour génération de trafic réel

## Success Criteria

1. ✅ PCAP généré avec retransmissions SYN (2-3 retrans, ~3s total)
2. ✅ PCAP généré avec retransmissions PSH,ACK  
3. ✅ CLI affiche les délais corrects (validé contre tshark)
4. ✅ Rapport HTML affiche les mêmes délais que le CLI
5. ✅ Tests automatisés validant la cohérence

## Test Methodology (TDD)

1. **Red Phase**: Écrire tests de validation des timings attendus
2. **Green Phase**: Générer PCAP, exécuter analyse, valider résultats
3. **Refactor**: Documenter les findings et corriger si divergence

## Environment

- **PCAP Generator**: Raspberry Pi via SSH
- **Analyzer**: Local avec venv activé
- **Validation**: tshark comme référence (ground truth)
