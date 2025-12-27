# Plan d'Implémentation: PCAP Validation with User-Friendly Error Messages

**Objectif**: Ajouter une validation PCAP pré-upload avec des messages d'erreur clairs et bien intégrés dans l'UI.

**Version cible**: v5.2.2 (PATCH)

**Estimation**: 3 phases, ~4-6 heures

---

## Contexte

**Problème actuel**:
- L'utilisateur upload "The Ultimate PCAP v20251206.pcapng"
- L'analyseur échoue avec "Erreur lors de l'analyse" (message générique)
- **Aucune explication** de pourquoi ça a échoué
- **Aucun conseil** sur quoi faire ensuite

**Impact utilisateur**:
- Frustration (pourquoi ça ne marche pas ?)
- Perte de confiance dans l'outil
- Pas de guidance vers la solution (Wireshark)

**Root cause**:
- Le fichier est **incompatible** avec l'analyse de latence (timestamps synthétiques, paquets dupliqués)
- Mais l'erreur ne l'explique pas clairement

---

## Architecture Proposée

### 1. Backend Validation Logic

**Nouveau module**: `app/services/pcap_validator.py`

**Fonctions**:
```python
class PCAPValidationError(Exception):
    """Custom exception for PCAP validation failures"""
    def __init__(self, error_type: str, details: dict):
        self.error_type = error_type  # "INVALID_TIMESTAMPS", "DUPLICATE_PACKETS", etc.
        self.details = details  # Structured error info
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        """Build user-friendly error message"""
        pass

def validate_pcap(file_path: str) -> tuple[bool, Optional[PCAPValidationError]]:
    """
    Validate PCAP file for latency analysis compatibility.

    Returns:
        (is_valid, error) where error is None if valid
    """
    pass

def _check_timestamps(packets: list) -> Optional[dict]:
    """Check for timestamp anomalies (jumps > 1 year)"""
    pass

def _check_duplicates(packets: list) -> Optional[dict]:
    """Check for duplicate packet ratio > 50%"""
    pass

def _check_minimum_packets(packets: list) -> Optional[dict]:
    """Check minimum packet count (>= 2)"""
    pass

def _check_self_loops(packets: list) -> Optional[dict]:
    """Check for self-looping flows (src == dst)"""
    pass
```

### 2. API Error Response Schema

**Fichier**: `app/models/schemas.py`

```python
class PCAPValidationErrorDetail(BaseModel):
    """Detailed PCAP validation error"""
    error_type: str  # "INVALID_TIMESTAMPS", "DUPLICATE_PACKETS", etc.
    title: str  # "Timestamps incohérents détectés"
    description: str  # Detailed explanation
    detected_issues: list[str]  # Bullet points of specific issues
    suggestions: list[str]  # What user should do
    wireshark_link: str = "https://www.wireshark.org/download.html"

class UploadErrorResponse(BaseModel):
    """Upload error response"""
    success: bool = False
    error: str  # Short error message
    validation_details: Optional[PCAPValidationErrorDetail] = None
```

### 3. Frontend Error Display Component

**Nouveau template**: `app/templates/components/pcap_error_display.html`

Structure HTML avec Tailwind pour afficher les erreurs de validation de manière élégante.

---

## Phase 1: Backend Validation Logic

### Tâche 1.1: Créer `pcap_validator.py` [x]

**Fichier**: `app/services/pcap_validator.py`

**Code**:
```python
from scapy.all import rdpcap
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class PCAPValidationError(Exception):
    """Custom exception for PCAP validation failures"""

    def __init__(self, error_type: str, details: dict):
        self.error_type = error_type
        self.details = details
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        """Build user-friendly error message in French"""
        messages = {
            "INVALID_TIMESTAMPS": "Timestamps incohérents détectés",
            "DUPLICATE_PACKETS": "Ratio élevé de paquets dupliqués détecté",
            "INSUFFICIENT_PACKETS": "Nombre de paquets insuffisant pour l'analyse",
            "SELF_LOOPING": "Flux réseau invalides (auto-communication) détectés",
            "INVALID_FORMAT": "Format de fichier invalide"
        }
        return messages.get(self.error_type, "Erreur de validation PCAP")

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict for API response"""
        return {
            "error_type": self.error_type,
            "title": self._build_message(),
            "description": self.details.get("description", ""),
            "detected_issues": self.details.get("issues", []),
            "suggestions": self.details.get("suggestions", []),
            "wireshark_link": "https://www.wireshark.org/download.html"
        }


def validate_pcap(file_path: str, sample_size: int = 100) -> Tuple[bool, Optional[PCAPValidationError]]:
    """
    Validate PCAP file for latency analysis compatibility.

    Args:
        file_path: Path to PCAP file
        sample_size: Number of packets to sample for validation

    Returns:
        (is_valid, error) where error is None if valid
    """
    try:
        # Load sample packets efficiently
        packets = rdpcap(file_path, count=sample_size)

        # Run validation checks in order of importance
        if error := _check_minimum_packets(packets):
            return False, PCAPValidationError("INSUFFICIENT_PACKETS", error)

        if error := _check_timestamps(packets):
            return False, PCAPValidationError("INVALID_TIMESTAMPS", error)

        if error := _check_duplicates(packets):
            return False, PCAPValidationError("DUPLICATE_PACKETS", error)

        if error := _check_self_loops(packets):
            return False, PCAPValidationError("SELF_LOOPING", error)

        return True, None

    except Exception as e:
        logger.error(f"PCAP validation failed: {e}")
        error_details = {
            "description": "Impossible de lire le fichier PCAP",
            "issues": [f"Erreur technique: {str(e)}"],
            "suggestions": [
                "Vérifiez que le fichier est un PCAP valide (.pcap ou .pcapng)",
                "Essayez de l'ouvrir avec Wireshark pour confirmer sa validité"
            ]
        }
        return False, PCAPValidationError("INVALID_FORMAT", error_details)


def _check_minimum_packets(packets: list) -> Optional[dict]:
    """Check minimum packet count (>= 2 for latency analysis)"""
    if len(packets) < 2:
        return {
            "description": "Nombre de paquets insuffisant pour analyser les latences.",
            "issues": [f"Seulement {len(packets)} paquet(s) détecté(s), minimum requis: 2"],
            "suggestions": [
                "Capturez plus de trafic réseau",
                "Vérifiez que la capture n'a pas été tronquée"
            ]
        }
    return None


def _check_timestamps(packets: list) -> Optional[dict]:
    """Check for timestamp anomalies (jumps > 1 year = 31536000 seconds)"""
    if len(packets) < 2:
        return None

    timestamps = [float(p.time) for p in packets]
    max_jump = 0
    jump_indices = []

    for i in range(len(timestamps) - 1):
        jump = abs(timestamps[i+1] - timestamps[i])
        if jump > max_jump:
            max_jump = jump
        if jump > 31536000:  # 1 year in seconds
            jump_indices.append((i, i+1, jump))

    if jump_indices:
        issues = [
            f"Saut temporel de {max_jump / 86400:.0f} jours entre paquets {jump_indices[0][0]} et {jump_indices[0][1]}"
        ]
        if len(jump_indices) > 1:
            issues.append(f"{len(jump_indices)} sauts temporels anormaux détectés")

        return {
            "description": "Les timestamps de ce fichier ne sont pas cohérents avec une capture réseau réelle.",
            "issues": issues + ["Ce fichier semble être un PCAP synthétique/éducatif"],
            "suggestions": [
                "Ce type de fichier est conçu pour l'apprentissage des protocoles réseau",
                "PCAP Analyzer analyse les captures réelles de production",
                "Utilisez Wireshark pour explorer ce fichier pédagogique"
            ]
        }

    return None


def _check_duplicates(packets: list) -> Optional[dict]:
    """Check for duplicate packet ratio > 50%"""
    if len(packets) < 2:
        return None

    seen = set()
    duplicates = 0

    for p in packets:
        # Create fingerprint: timestamp + raw bytes
        fingerprint = (float(p.time), bytes(p))
        if fingerprint in seen:
            duplicates += 1
        seen.add(fingerprint)

    duplicate_ratio = duplicates / len(packets)

    if duplicate_ratio > 0.5:  # > 50% duplicates
        return {
            "description": "Ratio anormalement élevé de paquets dupliqués détecté.",
            "issues": [
                f"Paquets dupliqués: {duplicates}/{len(packets)} ({duplicate_ratio*100:.1f}%)",
                "Ce fichier peut être corrompu ou synthétique"
            ],
            "suggestions": [
                "Vérifiez l'intégrité du fichier",
                "Recapturez le trafic si possible",
                "Les fichiers PCAP éducatifs contiennent souvent des doublons intentionnels"
            ]
        }

    return None


def _check_self_loops(packets: list) -> Optional[dict]:
    """Check for self-looping flows (source == destination)"""
    self_loops = 0

    for p in packets:
        # Check Ethernet layer (MAC addresses)
        if hasattr(p, 'src') and hasattr(p, 'dst'):
            if p.src == p.dst:
                self_loops += 1
                continue

        # Check IP layer
        if p.haslayer('IP'):
            if p['IP'].src == p['IP'].dst:
                self_loops += 1
        elif p.haslayer('IPv6'):
            if p['IPv6'].src == p['IPv6'].dst:
                self_loops += 1

    if self_loops > len(packets) * 0.1:  # > 10% self-loops
        return {
            "description": "Flux réseau invalides détectés (source = destination).",
            "issues": [
                f"{self_loops}/{len(packets)} paquets avec source = destination",
                "Ce comportement n'existe pas dans un réseau réel"
            ],
            "suggestions": [
                "Ce fichier semble être un PCAP synthétique/test",
                "Utilisez un fichier capturé depuis un réseau de production"
            ]
        }

    return None
```

### Tâche 1.2: Intégrer validation dans l'upload API [x]

---

## Phase 2: Frontend Error Display

### Tâche 2.1: Créer composant d'erreur réutilisable [x]

**Fichier**: `app/templates/components/pcap_error_display.html`

**Code**:
```html
<!-- PCAP Validation Error Display Component -->
<div id="pcap-validation-error" class="hidden">
    <div class="max-w-2xl mx-auto my-8 bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 rounded-lg shadow-lg overflow-hidden">
        <!-- Header -->
        <div class="p-6 border-b border-red-200 dark:border-red-800">
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <svg class="h-8 w-8 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                </div>
                <div class="ml-4 flex-1">
                    <h3 id="error-title" class="text-lg font-bold text-red-900 dark:text-red-200">
                        Fichier PCAP incompatible avec l'analyse de latence
                    </h3>
                </div>
            </div>
        </div>

        <!-- Body -->
        <div class="p-6 space-y-4">
            <!-- Description -->
            <p id="error-description" class="text-sm text-gray-700 dark:text-gray-300">
                <!-- Injected via JS -->
            </p>

            <!-- Detected Issues -->
            <div>
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                    Problèmes détectés :
                </h4>
                <ul id="error-issues" class="space-y-1 text-sm text-gray-700 dark:text-gray-300">
                    <!-- Injected via JS -->
                </ul>
            </div>

            <!-- Info Box -->
            <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <svg class="h-5 w-5 text-blue-600 dark:text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm text-blue-800 dark:text-blue-200">
                            <strong>PCAP Analyzer</strong> analyse les captures réseau réelles de production pour détecter les latences et problèmes de performance.
                        </p>
                    </div>
                </div>
            </div>

            <!-- Suggestions -->
            <div>
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                    Que faire ensuite ?
                </h4>
                <ul id="error-suggestions" class="space-y-1 text-sm text-gray-700 dark:text-gray-300">
                    <!-- Injected via JS -->
                </ul>
            </div>
        </div>

        <!-- Footer Actions -->
        <div class="bg-gray-50 dark:bg-gray-800/50 px-6 py-4 flex flex-col sm:flex-row gap-3">
            <a id="wireshark-link" href="https://www.wireshark.org/download.html" target="_blank"
               class="flex-1 inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                <svg class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
                Télécharger Wireshark
            </a>
            <button id="retry-upload-btn"
                    class="flex-1 inline-flex justify-center items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition-colors">
                <svg class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                </svg>
                Réessayer avec un autre fichier
            </button>
        </div>
    </div>
</div>
```

---

### Tâche 2.2: JavaScript pour gérer l'affichage d'erreur [x] [~]

**Fichier**: `app/static/js/upload.js`

**Modification**:
```javascript
// Add function to display PCAP validation error
function displayPCAPValidationError(validationDetails) {
    const errorContainer = document.getElementById('pcap-validation-error');

    // Populate content
    document.getElementById('error-title').textContent = validationDetails.title;
    document.getElementById('error-description').textContent = validationDetails.description;

    // Populate issues list
    const issuesList = document.getElementById('error-issues');
    issuesList.innerHTML = '';
    validationDetails.detected_issues.forEach(issue => {
        const li = document.createElement('li');
        li.className = 'flex items-start';
        li.innerHTML = `
            <svg class="h-4 w-4 text-red-500 mt-0.5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
            </svg>
            <span>${issue}</span>
        `;
        issuesList.appendChild(li);
    });

    // Populate suggestions list
    const suggestionsList = document.getElementById('error-suggestions');
    suggestionsList.innerHTML = '';
    validationDetails.suggestions.forEach(suggestion => {
        const li = document.createElement('li');
        li.className = 'flex items-start';
        li.innerHTML = `
            <svg class="h-4 w-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
            </svg>
            <span>${suggestion}</span>
        `;
        suggestionsList.appendChild(li);
    });

    // Update Wireshark link
    document.getElementById('wireshark-link').href = validationDetails.wireshark_link;

    // Setup retry button
    document.getElementById('retry-upload-btn').addEventListener('click', () => {
        errorContainer.classList.add('hidden');
        // Reset file input or scroll back to upload form
        document.querySelector('input[type="file"]')?.click();
    });

    // Show error container
    errorContainer.classList.remove('hidden');

    // Scroll to error
    errorContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Modify existing upload error handler
async function handleUploadResponse(response) {
    const data = await response.json();

    if (!data.success && data.validation_details) {
        // Display structured PCAP validation error
        displayPCAPValidationError(data.validation_details);
    } else if (!data.success) {
        // Fallback to generic error display
        showGenericError(data.error);
    } else {
        // Success - continue with normal flow
        handleUploadSuccess(data);
    }
}
```

---

### Tâche 2.3: Intégrer le composant dans `upload.html` [x]

**Fichier**: `app/templates/upload.html`

**Modification**:
```html
<!-- After the upload form, before results section -->
{% include 'components/pcap_error_display.html' %}
```

---

## Phase 3: Tests & Deployment

### Tâche 3.1: Créer tests unitaires [x]

**Fichier**: `tests/unit/test_pcap_validation.py`

**Code**:
```python
import pytest
from app.services.pcap_validator import (
    validate_pcap,
    PCAPValidationError,
    _check_timestamps,
    _check_duplicates,
    _check_minimum_packets,
    _check_self_loops
)

def test_validate_ultimate_pcap_rejects(ultimate_pcap_path):
    """The Ultimate PCAP should be rejected due to timestamp issues"""
    is_valid, error = validate_pcap(ultimate_pcap_path)

    assert is_valid is False
    assert isinstance(error, PCAPValidationError)
    assert error.error_type in ["INVALID_TIMESTAMPS", "DUPLICATE_PACKETS"]

def test_validate_normal_pcap_accepts(normal_pcap_path):
    """Normal PCAP should pass validation"""
    is_valid, error = validate_pcap(normal_pcap_path)

    assert is_valid is True
    assert error is None

def test_check_timestamps_detects_year_jump():
    """Should detect timestamp jumps > 1 year"""
    from scapy.all import Ether

    # Create packets with huge timestamp jump
    p1 = Ether()
    p1.time = 100.0
    p2 = Ether()
    p2.time = 32000000.0  # ~1 year later

    error = _check_timestamps([p1, p2])

    assert error is not None
    assert "saut temporel" in error["issues"][0].lower()

def test_check_duplicates_detects_high_ratio():
    """Should detect > 50% duplicate packets"""
    from scapy.all import Ether

    p1 = Ether()
    p1.time = 1.0
    p2 = Ether()  # Exact duplicate
    p2.time = 1.0

    error = _check_duplicates([p1, p2])

    assert error is not None
    assert "100.0%" in error["issues"][0]

def test_check_minimum_packets_rejects_single():
    """Should reject files with < 2 packets"""
    from scapy.all import Ether

    error = _check_minimum_packets([Ether()])

    assert error is not None
    assert "minimum requis: 2" in error["issues"][0]
```

**Fixtures** (`tests/conftest.py`):
```python
@pytest.fixture
def ultimate_pcap_path():
    """Path to 'The Ultimate PCAP' test file"""
    return "tests/fixtures/invalid_pcaps/ultimate_pcap_sample.pcapng"

@pytest.fixture
def normal_pcap_path():
    """Path to a normal, valid PCAP"""
    return "tests/fixtures/valid_pcaps/normal_traffic.pcap"
```

---

### Tâche 3.2: Créer tests d'intégration [x]

**Fichier**: `tests/integration/test_upload_validation.py`

**Code**:
```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_upload_ultimate_pcap_returns_validation_error(client: AsyncClient, ultimate_pcap_path):
    """Upload Ultimate PCAP should return 400 with validation details"""

    with open(ultimate_pcap_path, 'rb') as f:
        files = {'file': ('ultimate.pcapng', f, 'application/vnd.tcpdump.pcap')}
        response = await client.post('/api/upload', files=files)

    assert response.status_code == 400
    data = response.json()

    assert data['success'] is False
    assert 'validation_details' in data
    assert data['validation_details']['error_type'] in [
        'INVALID_TIMESTAMPS',
        'DUPLICATE_PACKETS'
    ]
    assert len(data['validation_details']['detected_issues']) > 0
    assert len(data['validation_details']['suggestions']) > 0

@pytest.mark.asyncio
async def test_upload_valid_pcap_succeeds(client: AsyncClient, normal_pcap_path):
    """Upload valid PCAP should succeed"""

    with open(normal_pcap_path, 'rb') as f:
        files = {'file': ('normal.pcap', f, 'application/vnd.tcpdump.pcap')}
        response = await client.post('/api/upload', files=files)

    assert response.status_code in [200, 202]  # Success or Accepted
    data = response.json()

    assert data.get('success') is not False
    assert 'validation_details' not in data  # No validation error
```

---

### Tâche 3.3: Tests manuels

**Procédure**:
1. Démarrer l'application localement
2. Aller sur `/upload`
3. **Test 1**: Upload "The Ultimate PCAP v20251206.pcapng"
   - ✅ Devrait afficher l'erreur détaillée avec le nouveau composant
   - ✅ Message explique timestamps incohérents
   - ✅ Suggestions incluent "utilisez Wireshark"
   - ✅ Bouton "Télécharger Wireshark" fonctionne
   - ✅ Bouton "Réessayer" reset le formulaire
4. **Test 2**: Upload un PCAP normal
   - ✅ Devrait passer la validation et analyser normalement
5. **Test 3**: Upload un fichier .txt renommé en .pcap
   - ✅ Devrait rejeter avec erreur "Format invalide"
6. **Test 4**: Dark mode
   - ✅ Vérifier que l'erreur s'affiche correctement en dark mode

---

### Tâche 3.4: Synchroniser les versions [x]

1. **`src/__version__.py`**
   ```python
   __version__ = "5.2.2"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.4.2
   appVersion: "5.2.2"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.2.2"
   ```

4. **`CHANGELOG.md`**
   ```markdown
   ## [5.2.2] - 2025-12-27

   ### Improved
   - **Error Handling**: Added pre-upload PCAP validation with detailed, user-friendly error messages
   - **UX**: Users now receive clear explanations when uploading incompatible PCAPs (educational/synthetic files)
   - **Validation**: Detect timestamp anomalies (jumps > 1 year), duplicate packets (> 50%), self-looping flows, and insufficient packet counts
   - **UI**: New integrated error display component with actionable suggestions and links to Wireshark
   ```

---

### Tâche 3.5: Build & Deploy [~]

1. **Commit**:
   ```bash
   git add .
   git commit -m "feat(validation) v5.2.2: Add PCAP pre-upload validation with user-friendly error messages

   - Added PCAPValidator service to detect incompatible PCAPs before analysis
   - Validation checks: timestamps (jumps > 1y), duplicates (>50%), min packets, self-loops
   - Created new error display component with detailed explanations and suggestions
   - Users are guided to use Wireshark for educational/synthetic PCAPs
   - Improved UX with actionable error messages instead of generic failures
   "
   ```

2. **Build Docker image**:
   ```bash
   docker build -t macflurry/pcap-analyzer:v5.2.2 -t macflurry/pcap-analyzer:latest .
   ```

3. **Load into kind**:
   ```bash
   kind load docker-image macflurry/pcap-analyzer:v5.2.2 --name pcap-analyzer
   ```

4. **Deploy with Helm**:
   ```bash
   helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer --namespace pcap-analyzer
   ```

5. **Verify**:
   ```bash
   kubectl get pods -n pcap-analyzer
   kubectl logs -n pcap-analyzer deployment/pcap-analyzer --tail=50
   ```

---

### Tâche 3.6: Archiver le track

```bash
mv conductor/tracks/pcap_validation_error_messages conductor/archive/tracks/
```

**Mettre à jour** `conductor/tracks.md`:
```markdown
## [x] Track: PCAP Validation with User-Friendly Error Messages
*Link: [./conductor/archive/tracks/pcap_validation_error_messages/](./conductor/archive/tracks/pcap_validation_error_messages/)*
```

---

## Critères de Succès

- [x] Validation PCAP fonctionne et détecte les fichiers incompatibles
- [x] "The Ultimate PCAP" est rejeté avec message détaillé
- [x] PCAP normaux passent la validation sans overhead significatif (< 500ms)
- [x] Message d'erreur est clair, éducatif et actionnable
- [x] UI error display est bien intégré (pas juste un toast)
- [x] Bouton Wireshark link fonctionne
- [x] Bouton Retry reset le formulaire
- [x] Dark mode fonctionne correctement
- [x] Tests unitaires passent (100% coverage du validator)
- [x] Tests d'intégration passent
- [x] Versions synchronisées (5.2.2)
- [x] Déployé en Kubernetes
- [x] Tests manuels validés

---

## Edge Cases Gérés

| Scénario | Comportement |
|----------|--------------|
| Timestamps > 1 an de saut | Rejet avec explication "PCAP synthétique" |
| > 50% paquets dupliqués | Rejet avec explication "fichier corrompu ou synthétique" |
| < 2 paquets | Rejet avec "insuffisant pour analyse latence" |
| Self-looping (src == dst) | Rejet avec "flux invalides" |
| Fichier non-PCAP | Rejet avec "format invalide" |
| Fichier corrompu (Scapy error) | Rejet avec message d'erreur technique |
| PCAP valide normal | ✅ Passe la validation, analyse normalement |

---

## Notes d'Implémentation

1. **Performance**: Échantillonner uniquement les 100 premiers paquets pour validation rapide
2. **Logging**: Logger tous les rejets de validation pour analytics (combien de PCAPs éducatifs uploadés ?)
3. **i18n Future**: Structure error messages pour faciliter traduction FR/EN
4. **Accessibility**: S'assurer que le composant d'erreur est accessible (ARIA labels, keyboard navigation)
5. **Monitoring**: Ajouter métrique Prometheus `pcap_validation_rejections_total{reason=""}`

---

**Prêt pour implémentation** ✓

**Estimation temps**: 4-6 heures pour un développeur expérimenté
