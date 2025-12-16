# Supmti Malware Scan

## Description
**Supmti Malware Scan** est un outil de vérification et d'analyse statique de fichiers pour aider à identifier des indicateurs potentiels de logiciels malveillants. Il fournit un ensemble d'analyses automatiques (hash, signatures connues, heuristiques simples) et génère un rapport récapitulatif.

>  **IMPORTANT :** Cet outil est destiné à un usage légal et éducatif uniquement. N'utilisez pas cet outil pour analyser des systèmes ou des fichiers dont vous n'êtes pas propriétaire ou sans autorisation explicite.

---

## Fonctionnalités
- Calcul de hash (MD5, SHA1, SHA256)
- Détection basée sur signatures simples
- Analyse heuristique minimale (patterns/texts suspicious)
- Génération de rapports au format JSON / texte
- Mode batch pour analyser plusieurs fichiers dans un dossier

---

## Prérequis
- Python 3.8+ (ou l'environnement approprié si le projet n'est pas en Python)
- Outils optionnels : `jq` pour manipuler les JSON en ligne de commande (facultatif)
- Fichiers de signatures (si fournis) ou accès à une base de données locale de règles

---

## Installation (exemple pour une version Python)
```bash
# Cloner le dépôt (ou décompresser l'archive fournie)
git clone https://github.com/owner/Supmti_Malware_Scan.git
cd Supmti_Malware_Scan

# Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate   # sur Linux/Mac
.venv\Scripts\activate      # sur Windows

# Installer les dépendances
pip install -r requirements.txt
