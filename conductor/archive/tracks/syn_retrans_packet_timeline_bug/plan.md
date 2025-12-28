# Plan d'Implémentation: SYN Retransmission Packet Timeline Bug Fix

**Version**: v5.2.3 (PATCH - bug critique data integrity)
**Estimated Effort**: 3-4 phases
**Test Coverage Target**: 95%+ for packet timeline logic

---

## Analyse Détaillée du Bug

### Symptômes Observés

**1. Mélange de TCP streams dans le timeline**

L'affichage "Handshake (First 10 Packets)" montre :
```
Frame 7422: tcp.stream 130 (port 1830)
Frame 7452: tcp.stream 129 (port 1829)
```

Mais le flow analysé est `tcp.stream 131` (port 1831) qui contient :
```
Frame 7458: SYN         (10.20.0.165:1831 → 2.19.147.191:80)
Frame 7462: SYN,ACK     (2.19.147.191:80 → 10.20.0.165:1831)
Frame 7492: SYN,ACK     [Retrans #1]
Frame 7608: SYN,ACK     [Retrans #2]
...
```

**Le frame 7458 (SYN initial) n'apparaît JAMAIS dans l'affichage!**

### Analyse Technique

#### Architecture Actuelle (src/analyzers/retransmission.py)

```python
# Ligne 383-384: Ring buffer per flow
self._packet_buffer: dict[str, deque] = {}  # flow_key -> deque(maxlen=10)

# Ligne 692-712: Ajout au buffer
if flow_key not in self._packet_buffer:
    self._packet_buffer[flow_key] = deque(maxlen=10)
packet_info = _create_simple_packet_info(...)
self._packet_buffer[flow_key].append(packet_info)  # deque automatically discards oldest

# Ligne 919-935: Capture du handshake lors de la première retransmission
if flow_key not in self.sampled_timelines:
    forward_handshake = list(self._packet_buffer[flow_key])  # ← BUG ICI?
    reverse_handshake = []
    if reverse_key in self._packet_buffer:
        reverse_handshake = list(self._packet_buffer[reverse_key])

    self.sampled_timelines[flow_key] = SampledTimeline(
        handshake=forward_handshake,
        ...
    )
```

#### Hypothèse #1: Contamination par Port Reuse

Le code ligne 468-472 nettoie les buffers lors de port reuse :
```python
# CRITICAL FIX v4.16.1: Clear packet buffers to prevent contamination
if flow_key in self._packet_buffer:
    del self._packet_buffer[flow_key]
if reverse_key in self._packet_buffer:
    del self._packet_buffer[reverse_key]
```

**Mais** : Le reset intervient APRÈS `should_reset_flow_state()` (ligne 719).
**Problème potentiel** : Si le reset n'est pas détecté à temps, les vieux paquets restent.

#### Hypothèse #2: flow_key Computation Bug

Le `flow_key` est généré avec :
```python
flow_key = f"{metadata.src_ip}:{metadata.src_port}->{metadata.dst_ip}:{metadata.dst_port}"
```

**Question** : Est-ce que le flow_key est correctement unique?
**Vérification nécessaire** : Logger les flow_keys pour confirmer unicité.

#### Hypothèse #3: Timing Issue avec deque(maxlen=10)

Le `deque(maxlen=10)` garde seulement les 10 **derniers** paquets.

**Scénario problématique** :
1. Flow 131 commence (frame 7458: SYN)
2. Buffer : [7458]
3. Frame 7462: SYN,ACK arrive
4. Buffer : [7458, 7462]
5. **Autres flows** (130, 129, etc.) continuent d'envoyer des paquets
6. **Si le même flow_key est partagé (BUG!)**, le buffer devient : [7422, 7452, 7458, 7462, ...]
7. Après 10 paquets, le deque éjecte 7458 → perte du SYN!
8. Quand la retransmission est détectée, le handshake capturé est pollué

#### Hypothèse #4: Problème de Diagnostic SYN Retrans

Le code détecte des SYN retransmissions mais classifie mal la cause :

```python
# Ligne 850-857: Détection SYN retransmission
is_syn_retrans = metadata.is_syn
retrans_type = "Retransmission"
if is_syn_retrans:
    if delay >= 0.5:
        retrans_type = "RTO"
```

**Le diagnostic devrait distinguer** :
- **SYN retrans (client)** : Server unreachable
- **SYN,ACK retrans (server)** : Client unreachable / unable to complete handshake

Dans le PCAP test, c'est le SERVER qui retransmet SYN,ACK, pas le client!

---

## Solution Proposée

### Phase 1: Diagnostic & Instrumentation

**Objectif** : Identifier la cause exacte avec logging

#### Tâche 1.1: Ajouter logging de flow_key [~]

```python
# Dans _process_metadata() ligne 652
flow_key = f"{metadata.src_ip}:{metadata.src_port}->{metadata.dst_ip}:{metadata.dst_port}"
reverse_key = f"{metadata.dst_ip}:{metadata.dst_port}->{metadata.src_ip}:{metadata.src_port}"

# LOG: Ajouter debug logging (à retirer après fix)
import logging
logger = logging.getLogger(__name__)
if metadata.is_syn or (flow_key in self.sampled_timelines):
    logger.debug(f"Packet {packet_num}: flow_key={flow_key}, buffer_size={len(self._packet_buffer.get(flow_key, []))}, is_syn={metadata.is_syn}")
```

#### Tâche 1.2: Vérifier unicité de flow_key

Ajouter assertions pour détecter les collisions :
```python
# Après création du buffer
if flow_key in self._packet_buffer:
    existing_flow = self.flow_stats.get(flow_key)
    if existing_flow:
        # Vérifier que src_ip/dst_ip/ports correspondent
        assert existing_flow.src_ip == metadata.src_ip, f"flow_key collision! {flow_key}"
        assert existing_flow.src_port == metadata.src_port, f"flow_key collision! {flow_key}"
```

#### Tâche 1.3: Test avec PCAP fourni

```bash
pytest tests/unit/analyzers/test_retransmission_timeline.py::test_syn_retrans_bug -v --log-cli-level=DEBUG
```

**Checkpoint Phase 1** : Identifier la cause racine avec certitude

---

### Phase 2: Fix du Packet Buffer

**Objectif** : S'assurer que le buffer contient UNIQUEMENT les paquets du bon flow

#### Tâche 2.1: Isolation stricte des buffers par flow

**Option A** : Valider que flow_key est déjà unique (probable)

**Option B** : Si collisions détectées, ajouter un ID unique :
```python
# Ajouter un compteur de connexion
self._connection_counter: dict[str, int] = {}

# Lors de nouveau SYN
if metadata.is_syn and flow_key not in self._initial_seq:
    self._connection_counter[flow_key] = self._connection_counter.get(flow_key, 0) + 1
    connection_id = f"{flow_key}#{self._connection_counter[flow_key]}"
    # Utiliser connection_id au lieu de flow_key pour le buffer
```

#### Tâche 2.2: Garantir capture du SYN initial

Le problème actuel : le deque(maxlen=10) peut éjecter le SYN si trop de paquets arrivent.

**Solution** : Lors d'un SYN, marquer explicitement le début du flow :

```python
# Ligne 744: Après détection SYN
if metadata.is_syn and flow_key not in self._initial_seq:
    self._initial_seq[flow_key] = metadata.tcp_seq
    # NOUVEAU: Capturer immédiatement le SYN comme "handshake start"
    if flow_key not in self._syn_packet:
        self._syn_packet[flow_key] = packet_info  # Sauvegarde permanente du SYN
```

Puis lors de la création du sampled_timeline :
```python
# Ligne 923: Modification capture handshake
forward_handshake = []
# 1. Toujours inclure le SYN s'il existe
if flow_key in self._syn_packet:
    forward_handshake.append(self._syn_packet[flow_key])
# 2. Ajouter les autres paquets du buffer (éviter duplicates)
buffer_packets = [p for p in self._packet_buffer[flow_key] if p.frame != forward_handshake[0].frame]
forward_handshake.extend(buffer_packets)
forward_handshake.sort(key=lambda p: p.timestamp)
forward_handshake = forward_handshake[:10]
```

#### Tâche 2.3: Reset complet lors de port reuse

S'assurer que `_syn_packet` est aussi nettoyé :
```python
# Ligne 468-472: Ajouter nettoyage _syn_packet
if flow_key in self._packet_buffer:
    del self._packet_buffer[flow_key]
if reverse_key in self._packet_buffer:
    del self._packet_buffer[reverse_key]

# NOUVEAU: Nettoyer aussi _syn_packet
if flow_key in self._syn_packet:
    del self._syn_packet[flow_key]
if reverse_key in self._syn_packet:
    del self._syn_packet[reverse_key]
```

**Checkpoint Phase 2** : Le handshake contient les bons frames du bon flow

---

### Phase 3: Fix du Diagnostic SYN Retrans

**Objectif** : Distinguer "server unreachable" vs "client unable to complete handshake"

#### Tâche 3.1: Détecter direction de SYN retransmission

```python
# Nouvelle méthode dans RetransmissionAnalyzer
def _classify_syn_retransmission(self, flow_key: str, metadata, retrans: TCPRetransmission) -> str:
    """
    Classify SYN retransmission as client-side or server-side failure.

    Returns:
        - "server_unreachable": Client SYN retransmissions (no SYN,ACK received)
        - "client_unreachable": Server SYN,ACK retransmissions (client didn't complete)
    """
    if not metadata.is_syn:
        return "not_syn_retrans"

    # Check if packet has ACK flag (SYN,ACK)
    if metadata.is_ack:
        # Server retransmitting SYN,ACK → Client unreachable
        return "client_unreachable"
    else:
        # Client retransmitting SYN → Server unreachable
        return "server_unreachable"
```

#### Tâche 3.2: Stocker classification dans TCPRetransmission

Ajouter nouveau champ :
```python
# Dans dataclass TCPRetransmission (ligne 48)
@dataclass
class TCPRetransmission:
    ...
    is_syn_retrans: bool = False
    tcp_flags: Optional[str] = None

    # NOUVEAU
    syn_retrans_direction: Optional[str] = None  # "server_unreachable" | "client_unreachable"
```

#### Tâche 3.3: Appliquer classification lors de détection

```python
# Ligne 893-915: Lors de création de TCPRetransmission
retrans = TCPRetransmission(
    ...
    is_syn_retrans=is_syn_retrans,
    tcp_flags=_tcp_flags_to_string(metadata=metadata),
    syn_retrans_direction=self._classify_syn_retransmission(flow_key, metadata, retrans) if is_syn_retrans else None,
)
```

#### Tâche 3.4: Afficher diagnostic correct dans HTML report

Modifier `src/exporters/html_report.py` :

```python
# Ligne ~2800: Section SYN Retransmissions
def _render_syn_retransmissions_section(self, syn_retrans_list):
    """Render SYN retransmissions with accurate diagnostics."""
    html = '<div class="anomaly-card">'
    html += '<h3 class="anomaly-title">🔴 SYN Retransmissions (Connection Failures) — {len(syn_retrans_list)} flows</h3>'

    for flow_key, retrans_group in syn_retrans_list:
        first_retrans = retrans_group[0]

        # Diagnostic basé sur direction
        if first_retrans.get('syn_retrans_direction') == 'server_unreachable':
            diagnostic = "Server unreachable (no SYN,ACK received)"
            explanation = "Client SYN retransmissions indicate the server is not responding."
        elif first_retrans.get('syn_retrans_direction') == 'client_unreachable':
            diagnostic = "Client unable to complete handshake (no final ACK)"
            explanation = "Server SYN,ACK retransmissions indicate the client is not completing the 3-way handshake."
        else:
            diagnostic = "Connection failed (cause unclear)"
            explanation = "Retransmission detected but direction could not be determined."

        html += f'<p><strong>{diagnostic}</strong></p>'
        html += f'<p><em>{explanation}</em></p>'
        ...
```

**Checkpoint Phase 3** : Diagnostic correctement affiché selon direction

---

### Phase 4: Tests & Validation

**Objectif** : Tests complets avec régression prevention

#### Tâche 4.1: Test unitaire avec PCAP fourni

```python
# tests/unit/analyzers/test_retransmission_timeline.py

def test_syn_retrans_correct_packet_timeline():
    """
    Test that SYN retransmission timeline shows correct frames from correct TCP stream.

    Regression test for bug where frames from wrong TCP streams appeared in timeline.
    Uses real PCAP: tests/data/syn_retrans_bug.pcap
    Flow: 10.20.0.165:1831 → 2.19.147.191:80 (tcp.stream 131)
    """
    from scapy.all import rdpcap
    from src.analyzers.retransmission import RetransmissionAnalyzer

    # Load test PCAP
    pcap_path = "tests/data/syn_retrans_bug.pcap"
    packets = rdpcap(pcap_path)

    # Analyze
    analyzer = RetransmissionAnalyzer()
    result = analyzer.analyze(packets)

    # Find flow 10.20.0.165:1831 → 2.19.147.191:80
    flow_key = "10.20.0.165:1831->2.19.147.191:80"
    assert flow_key in analyzer.sampled_timelines, f"Flow {flow_key} not found in sampled_timelines"

    timeline = analyzer.sampled_timelines[flow_key]
    handshake = timeline.handshake

    # Verify handshake contains correct frames (tcp.stream 131 only)
    expected_frames = {7458, 7462}  # SYN + SYN,ACK (first 2 packets of stream 131)
    actual_frames = {pkt.frame for pkt in handshake if pkt.frame in expected_frames}

    # CRITICAL: Must include frame 7458 (SYN)
    assert 7458 in actual_frames, "Missing SYN packet (frame 7458) in handshake!"

    # CRITICAL: Must NOT include frames from other streams
    wrong_frames = {7422, 7452, 7566, 7574, 7947, 8052}  # Frames from tcp.stream 130, 129, 137, 104
    actual_wrong = {pkt.frame for pkt in handshake if pkt.frame in wrong_frames}
    assert len(actual_wrong) == 0, f"Handshake contains frames from wrong TCP streams: {actual_wrong}"

    # Verify all handshake packets belong to correct flow
    for pkt in handshake:
        assert pkt.src_ip == "10.20.0.165" or pkt.src_ip == "2.19.147.191", f"Wrong src_ip: {pkt.src_ip}"
        assert pkt.dst_ip == "10.20.0.165" or pkt.dst_ip == "2.19.147.191", f"Wrong dst_ip: {pkt.dst_ip}"
        assert pkt.src_port == 1831 or pkt.src_port == 80, f"Wrong src_port: {pkt.src_port}"
        assert pkt.dst_port == 1831 or pkt.dst_port == 80, f"Wrong dst_port: {pkt.dst_port}"


def test_syn_retrans_diagnostic_client_unreachable():
    """
    Test that SYN,ACK retransmissions are correctly diagnosed as "client unreachable".

    Regression test for bug where tool showed "server unreachable" when actually
    server WAS reachable (sending SYN,ACK) but client didn't complete handshake.
    """
    from scapy.all import rdpcap
    from src.analyzers.retransmission import RetransmissionAnalyzer

    pcap_path = "tests/data/syn_retrans_bug.pcap"
    packets = rdpcap(pcap_path)

    analyzer = RetransmissionAnalyzer()
    result = analyzer.analyze(packets)

    # Find SYN retransmissions for flow 10.20.0.165:1831 → 2.19.147.191:80
    syn_retrans = [r for r in analyzer.retransmissions if r.is_syn_retrans and r.dst_port == 1831]

    assert len(syn_retrans) > 0, "No SYN retransmissions found"

    # All should be SYN,ACK retransmissions (tcp_flags contains both SYN and ACK)
    for retrans in syn_retrans:
        assert "SYN" in retrans.tcp_flags, f"Expected SYN flag in {retrans.tcp_flags}"
        assert "ACK" in retrans.tcp_flags, f"Expected ACK flag in {retrans.tcp_flags}"

        # Diagnostic should be "client_unreachable" not "server_unreachable"
        assert retrans.syn_retrans_direction == "client_unreachable", \
            f"Wrong diagnosis: {retrans.syn_retrans_direction} (expected client_unreachable)"
```

#### Tâche 4.2: Test de non-régression

Vérifier que les autres flows ne sont pas cassés :

```python
def test_no_regression_on_normal_flows():
    """Ensure fix doesn't break normal flow analysis."""
    from scapy.all import rdpcap
    from src.analyzers.retransmission import RetransmissionAnalyzer

    # Use existing test PCAPs
    test_files = [
        "tests/data/test_small.pcap",
        "tests/data/test_retransmissions.pcap",
        "tests/data/test_fast_retrans.pcap",
    ]

    for pcap_file in test_files:
        if not os.path.exists(pcap_file):
            continue

        packets = rdpcap(pcap_file)
        analyzer = RetransmissionAnalyzer()
        result = analyzer.analyze(packets)

        # Verify all sampled timelines have valid data
        for flow_key, timeline in analyzer.sampled_timelines.items():
            # Handshake packets should all belong to same flow
            if timeline.handshake:
                flow_ips_ports = set()
                for pkt in timeline.handshake:
                    flow_ips_ports.add((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))
                    flow_ips_ports.add((pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port))  # reverse

                # Should have at most 2 unique combinations (forward + reverse)
                assert len(flow_ips_ports) <= 2, f"Flow {flow_key} has packets from multiple flows: {flow_ips_ports}"
```

#### Tâche 4.3: Test E2E avec HTML report

Générer un report HTML et vérifier visuellement :

```bash
python -m src.cli analyze tests/data/syn_retrans_bug.pcap --format html --output /tmp/syn_retrans_test.html

# Ouvrir dans navigateur
open /tmp/syn_retrans_test.html

# Vérifier manuellement:
# 1. Section "SYN Retransmissions" affiche "Client unable to complete handshake"
# 2. Handshake timeline montre frames 7458, 7462 (PAS 7422, 7452)
# 3. Tous les paquets ont src/dst port = 1831 ou 80
```

#### Tâche 4.4: Update version & changelog

```bash
# src/__version__.py
__version__ = "5.2.3"

# CHANGELOG.md
## [5.2.3] - 2025-12-28

### Fixed
- **CRITICAL**: Packet timeline showing frames from wrong TCP streams (issue #XXX)
  - Handshake section now correctly filters packets by flow
  - SYN packet (first packet of handshake) no longer missing
  - Added permanent SYN packet storage to prevent loss in ring buffer
- SYN retransmission diagnostic now distinguishes:
  - SYN retrans (client) → "Server unreachable"
  - SYN,ACK retrans (server) → "Client unable to complete handshake"

### Tests
- Added regression test with real PCAP (`tests/data/syn_retrans_bug.pcap`)
- Verified no regression on existing test suite
```

**Checkpoint Phase 4** : Tous les tests passent, version bumped, ready to deploy

---

## Fichiers Modifiés

### Code Source

1. **src/analyzers/retransmission.py** (CRITICAL)
   - Ajouter `_syn_packet: dict[str, SimplePacketInfo]` pour stocker SYN initial
   - Modifier capture handshake (ligne ~923) pour garantir inclusion du SYN
   - Ajouter `_classify_syn_retransmission()` method
   - Nettoyer `_syn_packet` lors de reset flow (ligne ~468)

2. **src/exporters/html_report.py**
   - Modifier affichage diagnostic SYN retrans (ligne ~2800)
   - Utiliser `syn_retrans_direction` field pour diagnostic précis

3. **src/__version__.py**
   - Bump to "5.2.3"

### Tests

4. **tests/unit/analyzers/test_retransmission_timeline.py** (NOUVEAU)
   - `test_syn_retrans_correct_packet_timeline()`
   - `test_syn_retrans_diagnostic_client_unreachable()`

5. **tests/unit/analyzers/test_retransmission_no_regression.py** (NOUVEAU)
   - `test_no_regression_on_normal_flows()`

### Data

6. **tests/data/syn_retrans_bug.pcap** (DÉJÀ COPIÉ)
   - Test PCAP avec tcp.stream 131 (7 packets)

### Documentation

7. **CHANGELOG.md**
   - Ajouter section v5.2.3

---

## Critères de Succès

- [ ] Frame 7458 (SYN) apparaît dans handshake timeline
- [ ] Aucun frame d'autres TCP streams (7422, 7452, etc.)
- [ ] Diagnostic "Client unable to complete handshake" affiché
- [ ] Test unitaire `test_syn_retrans_correct_packet_timeline()` passe
- [ ] Test unitaire `test_syn_retrans_diagnostic_client_unreachable()` passe
- [ ] Aucune régression sur suite de tests existante
- [ ] HTML report généré correctement avec bon diagnostic

---

## Sécurité & Edge Cases

### Edge Cases Gérés

1. **Port Reuse** : Le code existant gère déjà port reuse avec `_reset_flow_state()`. Le fix ajoute nettoyage de `_syn_packet`.

2. **Très Gros Flows** : Le deque(maxlen=10) limite la mémoire. Avec l'ajout de `_syn_packet`, on stocke seulement 1 paquet supplémentaire par flow → négligeable.

3. **SYN sans SYN,ACK** : Si le serveur ne répond jamais, il n'y aura que le SYN dans le handshake → correct.

4. **Multiples SYN retrans du client** : Le premier SYN est stocké dans `_syn_packet`, les autres dans le buffer.

### Rollback Plan

Si le fix cause des problèmes :
```bash
git revert <commit-hash>
# Redeploy v5.2.2
```

---

## Prêt pour implémentation ✓
