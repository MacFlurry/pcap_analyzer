# Guide de Test - Nouvelle UX Page de Progression

## Pré-requis

- Serveur Flask en cours d'exécution
- Fichier PCAP de test disponible
- Navigateur moderne (Chrome, Firefox, Safari, Edge)

---

## Tests à effectuer

### 1. Test de l'état initial (Pending)

**Étapes:**
1. Uploader un fichier PCAP
2. Observer la page de progression immédiatement après upload

**Vérifications:**
- [ ] Header affiche "📈 Analyse en cours"
- [ ] Nom de fichier affiche le nom du fichier (PAS "Chargement...")
- [ ] Badge affiche "[⏳ En attente]" ou "[🔄 En cours]"
- [ ] Cercle à 0%
- [ ] Phase: "En attente" ou "Extraction métadonnées"
- [ ] Analyseur: "En attente" ou nom de l'analyseur
- [ ] Message: "En attente de démarrage..." ou message approprié
- [ ] Pas de texte "Chargement..." visible

### 2. Test de progression (Processing)

**Étapes:**
1. Observer la progression pendant l'analyse
2. Vérifier les mises à jour en temps réel

**Vérifications:**
- [ ] Cercle de progression s'anime de 0% à 100%
- [ ] Animation fluide (pas de sauts brusques)
- [ ] Barre linéaire suit le cercle
- [ ] Phase change: "Extraction métadonnées" → "Analyse des paquets" → "Finalisation"
- [ ] Nombre de paquets augmente progressivement
- [ ] Analyseur change dynamiquement
- [ ] Durée s'incrémente chaque seconde
- [ ] Journal d'événements se remplit
- [ ] Badge reste "En cours" avec spinner animé
- [ ] Nom de fichier reste affiché (ne revient pas à "Chargement...")

### 3. Test de complétion (Completed)

**Étapes:**
1. Attendre la fin de l'analyse
2. Observer l'état final

**Vérifications:**
- [ ] Cercle à 100% (vert)
- [ ] Badge affiche "[✅ Terminé]"
- [ ] Phase: "Terminé"
- [ ] Analyseur: "Terminé"
- [ ] Message: "Analyse terminée avec succès"
- [ ] Boutons d'action apparaissent dans une card glass:
  - [ ] "Voir le rapport HTML" (bouton vert)
  - [ ] "Télécharger JSON" (bouton gris)
  - [ ] "Nouvelle analyse" (bouton outline)
- [ ] Journal affiche "✓ Analyse terminée avec succès"
- [ ] Timer arrêté
- [ ] Score de santé affiché dans le journal

### 4. Test des boutons d'action

**Étapes:**
1. Cliquer sur "Voir le rapport HTML"
2. Cliquer sur "Télécharger JSON"
3. Cliquer sur "Nouvelle analyse"

**Vérifications:**
- [ ] Rapport HTML s'ouvre dans un nouvel onglet
- [ ] JSON se télécharge correctement
- [ ] "Nouvelle analyse" redirige vers la page d'upload

### 5. Test dark mode

**Étapes:**
1. Activer le dark mode
2. Observer tous les états (pending, processing, completed)

**Vérifications:**
- [ ] Toutes les cards ont un fond sombre
- [ ] Gradients adaptés au dark mode
- [ ] Textes lisibles (contraste suffisant)
- [ ] Glassmorphism fonctionne (transparence + blur)
- [ ] Badges lisibles
- [ ] Journal d'événements lisible
- [ ] Pas de flash blanc

### 6. Test responsive

**Étapes:**
1. Tester sur différentes tailles d'écran:
   - Desktop (>1024px)
   - Tablet (768-1024px)
   - Mobile (<768px)

**Vérifications Desktop:**
- [ ] Layout en grille (2/3 cercle + 1/3 stats)
- [ ] Tout visible sans scroll horizontal

**Vérifications Tablet:**
- [ ] Layout empilé (cercle au-dessus, stats en dessous)
- [ ] Pas de débordement

**Vérifications Mobile:**
- [ ] Layout vertical
- [ ] Cercle réduit mais visible
- [ ] Stats empilées
- [ ] Boutons full-width
- [ ] Texte lisible

### 7. Test des cartes de statistiques

**Étapes:**
1. Observer les 4 cartes de stats
2. Passer la souris dessus

**Vérifications:**
- [ ] Phase: Dégradé bleu (from-blue-50 to-blue-100)
- [ ] Paquets: Dégradé vert (from-green-50 to-green-100)
- [ ] Analyseur: Dégradé violet (from-purple-50 to-purple-100)
- [ ] Durée: Dégradé orange (from-orange-50 to-orange-100)
- [ ] Icônes sur fond blanc avec ombre
- [ ] Bordures colorées assorties
- [ ] Effet hover: translateY(-2px)
- [ ] Texte bold et lisible

### 8. Test des animations

**Étapes:**
1. Observer les animations pendant l'analyse

**Vérifications:**
- [ ] Cercle de progression: stroke-dashoffset animé
- [ ] Barre linéaire: width animé
- [ ] Badge "En cours": spinner qui tourne
- [ ] Stats: gradient-shift au survol
- [ ] Journal: slide-in-right pour nouveaux événements
- [ ] Cercle: drop-shadow purple/blue visible

### 9. Test du journal d'événements

**Étapes:**
1. Observer le journal pendant l'analyse
2. Vérifier le scroll si >50 événements

**Vérifications:**
- [ ] Nouveaux événements apparaissent en haut
- [ ] Icônes colorées par type:
  - [ ] ℹ️ Info (bleu)
  - [ ] ✓ Success (vert)
  - [ ] ⚠️ Warning (orange)
  - [ ] ✗ Error (rouge)
- [ ] Timestamps affichés
- [ ] Fond coloré par événement
- [ ] Animation slide-in-right
- [ ] Scroll fonctionne (max-h-96)
- [ ] Max 50 événements conservés

### 10. Test de reconnexion SSE

**Étapes:**
1. Pendant l'analyse, arrêter le serveur
2. Redémarrer le serveur
3. Observer le comportement

**Vérifications:**
- [ ] Message "⚠ Perte de connexion" dans le journal
- [ ] Message "Tentative de reconnexion..." après 3s
- [ ] Reconnexion réussie
- [ ] Progression reprend

### 11. Test fallback polling

**Étapes:**
1. Si SSE ne fonctionne pas, le polling devrait prendre le relais
2. Observer les mises à jour (toutes les 3s)

**Vérifications:**
- [ ] Mises à jour reçues même sans SSE
- [ ] Complétion détectée
- [ ] Boutons apparaissent

### 12. Test copie Task ID

**Étapes:**
1. Cliquer sur l'icône copie à côté du Task ID
2. Coller dans un éditeur de texte

**Vérifications:**
- [ ] Task ID copié dans le presse-papier
- [ ] Toast de confirmation (si implémenté)

### 13. Test états d'erreur

**Étapes:**
1. Simuler une erreur (fichier invalide, etc.)
2. Observer l'état d'échec

**Vérifications:**
- [ ] Badge affiche "[❌ Échec]"
- [ ] Cercle à 0%
- [ ] Phase: "Échec"
- [ ] Analyseur: "Échec"
- [ ] Message d'erreur affiché en rouge
- [ ] Card d'erreur apparaît avec:
  - [ ] Icône ⚠️
  - [ ] Titre "Analyse échouée"
  - [ ] Message d'erreur détaillé
  - [ ] Bouton "Réessayer avec un autre fichier"
- [ ] Journal affiche "✗ [message d'erreur]"
- [ ] Toast d'erreur affiché

### 14. Test état expiré

**Étapes:**
1. Accéder à une analyse terminée il y a >24h
2. Observer l'état expiré

**Vérifications:**
- [ ] Badge affiche "[⏰ Expiré]"
- [ ] Cercle à 100%
- [ ] Message: "Analyse terminée (rapport expiré)"
- [ ] Card d'avertissement avec:
  - [ ] Icône ⏳
  - [ ] Titre "Rapport expiré"
  - [ ] Message "Les rapports ont expiré..."
  - [ ] Bouton "Nouvelle analyse"
- [ ] Pas de boutons "Voir rapport"
- [ ] Journal affiche "⏰ Analyse expirée (24h)"

### 15. Test glassmorphism

**Étapes:**
1. Observer les cards avec un fond coloré derrière
2. Activer/désactiver le dark mode

**Vérifications:**
- [ ] Cards semi-transparentes
- [ ] Effet blur visible
- [ ] Gradient background visible
- [ ] Ombres douces
- [ ] Bordures subtiles
- [ ] Dark mode: transparence adaptée

---

## Checklist de validation finale

### Bugs corrigés
- [ ] ✅ "Chargement..." ne reste jamais affiché
- [ ] ✅ Nom de fichier s'affiche dès que disponible
- [ ] ✅ Tous les états ont des textes appropriés

### Design cohérent
- [ ] ✅ Glassmorphism appliqué partout
- [ ] ✅ Gradients purple/blue cohérents
- [ ] ✅ Palette de couleurs respectée
- [ ] ✅ Typography unifiée
- [ ] ✅ Même style que historique/upload

### Agencement optimal
- [ ] ✅ Layout en grille 2/3 + 1/3
- [ ] ✅ Cercle agrandi (240px)
- [ ] ✅ Stats colorées et organisées
- [ ] ✅ Responsive sur tous devices
- [ ] ✅ Espace bien utilisé

### Fonctionnalités
- [ ] ✅ SSE temps réel
- [ ] ✅ Préchargement status
- [ ] ✅ Smooth progress
- [ ] ✅ Fallback polling
- [ ] ✅ Timer durée
- [ ] ✅ Journal événements
- [ ] ✅ Boutons action
- [ ] ✅ Tous états gérés (5/5)
- [ ] ✅ Dark mode complet
- [ ] ✅ Animations fluides

---

## Tests de performance

### Temps de chargement
- [ ] Page charge en <1s
- [ ] Animations fluides (60fps)
- [ ] Pas de lag au scroll

### Mémoire
- [ ] Pas de fuite mémoire (laisser tourner 5min)
- [ ] Journal limité à 50 événements
- [ ] Timers nettoyés à la fin

---

## Tests de compatibilité navigateurs

### Chrome
- [ ] Toutes fonctionnalités OK
- [ ] Animations fluides
- [ ] Dark mode OK
- [ ] SSE OK

### Firefox
- [ ] Toutes fonctionnalités OK
- [ ] Animations fluides
- [ ] Dark mode OK
- [ ] SSE OK

### Safari
- [ ] Toutes fonctionnalités OK
- [ ] Animations fluides
- [ ] Dark mode OK
- [ ] SSE OK

### Edge
- [ ] Toutes fonctionnalités OK
- [ ] Animations fluides
- [ ] Dark mode OK
- [ ] SSE OK

---

## Tests accessibilité

### Navigation clavier
- [ ] Tab pour naviguer
- [ ] Boutons activables avec Enter
- [ ] Focus visible

### Lecteur d'écran
- [ ] Textes alternatifs présents
- [ ] Titres hiérarchisés
- [ ] ARIA labels appropriés

### Contraste
- [ ] Textes lisibles (WCAG AA)
- [ ] Dark mode respecte les contrastes

---

## Rapport de bug

Si vous trouvez un bug, notez:

**Environnement:**
- Navigateur: [Chrome/Firefox/Safari/Edge]
- Version: [XX.X]
- OS: [Windows/macOS/Linux/iOS/Android]
- Résolution: [XXXXxXXXX]
- Dark mode: [Oui/Non]

**Reproduction:**
1. [Étape 1]
2. [Étape 2]
3. [Étape 3]

**Résultat attendu:**
[Description]

**Résultat obtenu:**
[Description]

**Captures d'écran:**
[Si possible]

---

## Validation finale

Avant de considérer la refonte comme terminée, tous les tests ci-dessus doivent passer avec succès.

**Status:** [ ] EN COURS / [ ] VALIDÉ

**Testé par:** ___________________

**Date:** ___________________

**Signature:** ___________________
