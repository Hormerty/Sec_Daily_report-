"""Ajoute un marqueur de statut lisible par machine a chaque source citee en gras."""
from pathlib import Path

DOCUMENT = Path(r"D:\Security Code GitHub\Sec_Daily_report-\SOURCES.md")
texte = DOCUMENT.read_text(encoding="utf-8")

# statut attendu, par nom de source tel qu'il apparait dans le lien.
STATUTS = {
    "vulneraibility.com": "refuse",
    "EUVD": "integre",
    "cve.now": "refuse",
    "OSV": "refuse",
    "CVEProject/cvelistV5": "accepte",
    "trickest/cve": "refuse",
    "alex-ilgayev/secfeed": "refuse",
    "SharonBrizinov/secfeed": "refuse",
}

ajoutes = 0
for nom, statut in STATUTS.items():
    ancre = f"**[{nom}]("
    i = texte.find(ancre)
    if i == -1:
        print("  introuvable :", nom)
        continue
    # Le marqueur va juste apres le lien, avant la fin du gras.
    fin_lien = texte.find(")", i)
    if "<!-- statut:" in texte[fin_lien:fin_lien + 60]:
        continue
    marqueur = f" <!-- statut: {statut} -->"
    texte = texte[:fin_lien + 1] + marqueur + texte[fin_lien + 1:]
    ajoutes += 1

DOCUMENT.write_text(texte, encoding="utf-8")
print(f"marqueurs ajoutes : {ajoutes}/8")
