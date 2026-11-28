"""Corrige le paragraphe EUVD de SOURCES.md, qui contredit le code depuis le 26 novembre."""
from pathlib import Path

DOCUMENT = Path(r"D:\Security Code GitHub\Sec_Daily_report-\SOURCES.md")
texte = DOCUMENT.read_text(encoding="utf-8")

debut = texte.index("**[EUVD]")
fin = texte.index("**[cve.now]", debut)

nouveau = """**[EUVD](https://euvd.enisa.europa.eu): ENISA's European Vulnerability Database** is
**integrated**, and this page said the opposite until 28 November 2026. The error was found by
re-reading the code: `collect_euvd` runs in the daily report and in the alert pass, against
`/api/kev/dump`, the European equivalent of the CISA catalogue: 1 783 entries carrying `cveId`,
`euvdId`, `dateAdded` and the sources. What made it look refused is the volume of `/api/search`:
294 entries on 25 November alone, mostly CERT-PL advisories we already collect directly. The
collector therefore reads the KEV dump, keeps only recent additions, and drops any CVE the
American KEV already lists, so the same flaw is not printed twice.

"""
texte = texte[:debut] + nouveau + texte[fin:]
DOCUMENT.write_text(texte, encoding="utf-8")
print("SOURCES.md : EUVD corrige")
print("cadratins :", texte.count("\u2014"))
