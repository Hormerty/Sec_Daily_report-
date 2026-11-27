"""Retire les six sources de bruit et ajoute la racine « securite des modeles »."""
from pathlib import Path

VEILLE = Path(r"D:\Security Code GitHub\Sec_Daily_report-\veille.py")
texte = VEILLE.read_text(encoding="utf-8")

# --- 1. Les declarations de sources --------------------------------------------------
lignes_a_retirer = [
    '{"name": "01net", "url": "https://www.01net.com/feed/", "category": NEWS, "filter": True, "max": 5},',
    '{"name": "Clubic", "url": "https://www.clubic.com/feed/rss", "category": NEWS, "filter": True, "max": 5},',
    '{"name": "Next", "url": "https://next.ink/feed/", "category": NEWS, "filter": True, "max": 5},',
    '{"name": "Korben", "url": "https://korben.info/feed", "category": BLOGS, "filter": True},',
    '{"name": "HackerSploit", "url": "https://hackersploit.org/feed/", "category": BLOGS},',
    '{"name": "NetworkChuck", "url": "https://networkchuck.com/feed/", "category": BLOGS},',
]
retirees = 0
for ligne in lignes_a_retirer:
    if ligne in texte:
        texte = texte.replace(ligne + "\n", "", 1)
        retirees += 1
    else:
        print("  ligne introuvable :", ligne[:60])
print(f"declarations retirees : {retirees}/6")

# --- 2. Leurs entrees dans les dictionnaires de poids et de liens --------------------
paires = [
    ('"01net": 0,', ""),
    ('"Clubic": 0,', ""),
    ('"Next": 1,', ""),
    ('"Korben": 0,', ""),
    ('"HackerSploit": 0,', ""),
    ('"NetworkChuck": 0,', ""),
]
for avant, apres in paires:
    if avant in texte:
        texte = texte.replace(avant + " ", "", 1).replace(avant, "", 1)
print("poids nettoyes")

# --- 3. La racine « securite des modeles » -------------------------------------------
ancre = 'r"pare-feu|dark ?web|darknet|sabotage|deepfake|rgpd|gdpr|pentest|bug bounty",'
assert ancre in texte, "motif introuvable"
remplacement = ('r"pare-feu|dark ?web|darknet|sabotage|deepfake|rgpd|gdpr|pentest|bug bounty|"\n'
                '    r"prompt injection|jailbreak|model extraction|guardrail",')
texte = texte.replace(ancre, remplacement, 1)
print("racine securite IA ajoutee")

VEILLE.write_text(texte, encoding="utf-8")
