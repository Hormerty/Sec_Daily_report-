"""Re-teste chaque source refusee dans SOURCES.md, et dit si le refus tient toujours.

Un refus date d'un jour precis, pour une raison precise. Six mois plus tard, le site a pu
changer d'adresse, ouvrir un flux, ou mourir. Ce script rejoue la mesure et affiche, a cote du
refus ecrit, ce que la source fait aujourd'hui.

    python tools/verifier_refus.py
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

RACINE = Path(__file__).resolve().parent.parent
DOCUMENT = RACINE / "SOURCES.md"
ENTETES = {"User-Agent": "Mozilla/5.0 (compatible; SecDailyBrief-audit)"}


def entrees() -> list[tuple[str, str]]:
    """(nom, url) des sources citees en gras dans la page."""
    texte = DOCUMENT.read_text(encoding="utf-8")
    return re.findall(r"\*\*\[([^\]]+)\]\((https?://[^)]+)\)[^*]*\*\*", texte)


def tester_depot(depot: str) -> str | None:
    """Etat d'un depot GitHub : etoiles, dernier push, licence, taille. None si ce n'est pas un depot."""
    entetes = dict(ENTETES, Accept="application/vnd.github+json")
    try:
        reponse = requests.get(f"https://api.github.com/repos/{depot}", headers=entetes, timeout=20)
    except requests.RequestException as exc:
        return f"depot illisible ({type(exc).__name__})"
    if reponse.status_code != 200:
        return f"depot {depot} : HTTP {reponse.status_code}"
    d = reponse.json()
    licence = (d.get("license") or {}).get("spdx_id") or "sans licence"
    return (f"depot {d.get('stargazers_count')} etoiles, pousse le {str(d.get('pushed_at'))[:10]}, "
            f"{licence}, {round((d.get('size') or 0) / 1024)} Mo")


def tester(url: str) -> str:
    """Une phrase sur ce que l'adresse repond aujourd'hui."""
    if "github.com/" in url:
        morceaux = url.rstrip("/").split("github.com/")[-1].split("/")
        if len(morceaux) >= 2:
            etat = tester_depot(f"{morceaux[0]}/{morceaux[1]}")
            if etat:
                return etat
    session = requests.Session()
    session.headers.update(ENTETES)
    try:
        reponse = session.get(url, timeout=25)
    except requests.RequestException as exc:
        return f"injoignable ({type(exc).__name__})"
    type_ = (reponse.headers.get("Content-Type") or "").split(";")[0]
    taille = len(reponse.content) // 1024
    if "xml" in type_ or "rss" in type_ or "atom" in type_:
        flux = feedparser.parse(reponse.content)
        dates = [e.get("published_parsed") or e.get("updated_parsed") for e in flux.entries]
        dates = [datetime(*d[:6], tzinfo=timezone.utc) for d in dates if d]
        dernier = max(dates).strftime("%d/%m/%Y") if dates else "aucune date"
        return (f"flux {flux.version or '?'} : {len(flux.entries)} entree(s), "
                f"derniere {dernier}, {taille} Ko")
    return f"HTTP {reponse.status_code}, {type_ or 'type inconnu'}, {taille} Ko"


def main() -> int:
    if not DOCUMENT.is_file():
        print(f"SOURCES.md introuvable : {DOCUMENT}", file=sys.stderr)
        return 2
    for nom, url in entrees():
        print(f"{nom}")
        print(f"  {url}")
        print(f"  aujourd hui : {tester(url)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
