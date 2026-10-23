#!/usr/bin/env python3
"""NourSECBot : Veille cybersécurité & OSINT exhaustive et intelligente."""
from __future__ import annotations

import html
import json
import logging
import os
import smtplib
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("noursecbot")

# --- Configuration & Fichier de persistance ---
SEEN_FILE = "seen.json"
FENETRE_HEURES = int(os.environ.get("FENETRE_HEURES", "36"))
MAX_PAR_SOURCE = 15
CISA_JOURS = int(os.environ.get("CISA_JOURS", "3"))
MAX_CISA = 25
TIMEOUT = 15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Mots-clés pour le marquage prioritaire (🇧🇪 / 🎯)
MOTS_CLES_BELGIQUE = ["belgique", "belgium", "belge", "wallonie", "ccb", "safeonweb"]
MOTS_CLES_CIBLES = ["exchange", "outlook", "node", "ivanti", "vmware", "citrix", "vpn", "ransomware"]

ORDRE_CATEGORIES = [
    "Alertes & vulnérabilités",
    "Dark web & ransomware",
    "Actualités & Médias",
    "Threat Intelligence",
    "Blogs & OSINT",
]

ALERTES = "Alertes & vulnérabilités"
DARKWEB = "Dark web & ransomware"
ACTUS = "Actualités & Médias"
INTEL = "Threat Intelligence"
BLOGS = "Blogs & OSINT"

# --- Sources RSS vérifiées et corrigées ---
SOURCES_RSS = [
    # CERT & Autorités
    {"nom": "CERT-FR avis", "url": "https://www.cert.ssi.gouv.fr/avis/feed/", "langue": "fr", "categorie": ALERTES},
    {"nom": "CERT-FR alertes", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/", "langue": "fr", "categorie": ALERTES},
    {"nom": "CERT-EU", "url": "https://cert.europa.eu/publications/security-advisories-rss", "langue": "en", "categorie": ALERTES},
    {"nom": "Safeonweb (Belgique)", "url": "https://safeonweb.be/fr/rss.xml", "langue": "fr", "categorie": ALERTES},
    {"nom": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "langue": "en", "categorie": ALERTES},
    
    # Dark web / Ransomware
    {"nom": "Ransomware.live", "url": "https://ransomware.live/cyberattacks.xml", "langue": "en", "categorie": DARKWEB},

    # Actualités & Médias
    {"nom": "The Record", "url": "https://therecord.media/feed", "langue": "en", "categorie": ACTUS},
    {"nom": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "langue": "en", "categorie": ACTUS},
    {"nom": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "langue": "en", "categorie": ACTUS},
    {"nom": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "langue": "en", "categorie": ACTUS},
    {"nom": "Ars Technica (Security)", "url": "https://arstechnica.com/tag/security/feed/", "langue": "en", "categorie": ACTUS},
    {"nom": "Next INpact", "url": "https://next.ink/feed/", "langue": "fr", "categorie": ACTUS},

    # Threat Intelligence
    {"nom": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "langue": "en", "categorie": INTEL},
    {"nom": "Unit 42 (Palo Alto)", "url": "https://unit42.paloaltonetworks.com/feed/", "langue": "en", "categorie": INTEL},
    {"nom": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/", "langue": "en", "categorie": INTEL},
    {"nom": "WeLiveSecurity (ESET)", "url": "https://www.welivesecurity.com/feed/", "langue": "en", "categorie": INTEL},
    {"nom": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "langue": "en", "categorie": INTEL},
    {"nom": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "langue": "en", "categorie": INTEL},

    # Blogs & OSINT
    {"nom": "Korben", "url": "https://korben.info/feed", "langue": "fr", "categorie": BLOGS},
    {"nom": "Zataz", "url": "https://www.zataz.com/feed/", "langue": "fr", "categorie": BLOGS},
    {"nom": "Hak5", "url": "https://www.hak5.org/blog/rss", "langue": "en", "categorie": BLOGS},
    {"nom": "HackerSploit", "url": "https://hackersploit.org/feed/", "langue": "en", "categorie": BLOGS},
    {"nom": "NetworkChuck", "url": "https://networkchuck.com/feed/", "langue": "en", "categorie": BLOGS},
    {"nom": "Bellingcat", "url": "https://www.bellingcat.com/feed/", "langue": "en", "categorie": BLOGS},
]
@dataclass
class Article:
    source: str
    titre: str
    lien: str
    date: datetime
    categorie: str = ALERTES
    detail: str = ""
    tags: str = ""

def charger_deja_vus() -> set[str]:
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def sauvegarder_deja_vus(vus: set[str]):
    liste_recente = list(vus)[-2000:]
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            json.dump(liste_recente, f)
    except Exception as exc:
        log.warning("Impossible de sauvegarder seen.json : %s", exc)

def creer_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT})
    return session

def analyser_tags(texte: str) -> str:
    texte_lower = texte.lower()
    marques = []
    if any(k in texte_lower for k in MOTS_CLES_BELGIQUE):
        marques.append("🇧🇪")
    if any(k in texte_lower for k in MOTS_CLES_CIBLES):
        marques.append("🎯")
    return " ".join(marques)

def collecter_rss(session: requests.Session, source: dict, depuis: datetime, deja_vus: set[str]):
    try:
        reponse = session.get(source["url"], timeout=TIMEOUT)
        reponse.raise_for_status()
    except requests.RequestException as exc:
        log.warning("%s : %s", source["nom"], exc)
        return [], f"{source['nom']} : {exc}"

    flux = feedparser.parse(reponse.content)
    articles = []
    for entree in flux.entries:
        t = entree.get("published_parsed") or entree.get("updated_parsed")
        if not t:
            continue
        date = datetime(*t[:6], tzinfo=timezone.utc)
        if date < depuis:
            continue
        
        lien = entree.get("link", source["url"])
        if lien in deja_vus:
            continue

        titre = entree.get("title", "Article sans titre")
        tags = analyser_tags(titre)

        articles.append(
            Article(
                source=source["nom"],
                titre=titre,
                lien=lien,
                date=date,
                categorie=source["categorie"],
                tags=tags
            )
        )
    articles.sort(key=lambda a: a.date, reverse=True)
    return articles[: source.get("max", MAX_PAR_SOURCE)], None

def collecter_cisa_kev(session: requests.Session, depuis: datetime, deja_vus: set[str]):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        reponse = session.get(url, timeout=TIMEOUT)
        reponse.raise_for_status()
        vulns = reponse.json().get("vulnerabilities", [])
    except (requests.RequestException, ValueError) as exc:
        return [], f"CISA KEV : {exc}"

    seuil_date = (datetime.now(timezone.utc) - timedelta(days=CISA_JOURS)).date()
    articles = []
    for v in vulns:
        try:
            date = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if date.date() < seuil_date:
            continue
        
        cve = v.get("cveID", "CVE inconnu")
        lien = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if lien in deja_vus:
            continue

        titre_brut = f"{cve} : {v.get('vendorProject', '?')} {v.get('product', '?')}"
        tags = analyser_tags(titre_brut + " " + v.get("shortDescription", ""))

        articles.append(
            Article(
                source="CISA KEV",
                titre=titre_brut,
                lien=lien,
                date=date,
                detail=v.get("shortDescription", ""),
                categorie=ALERTES,
                tags=tags
            )
        )
    articles.sort(key=lambda a: a.date, reverse=True)
    return articles[:MAX_CISA], None
def rendre_html(groupes: dict[str, list[Article]], erreurs: list[str]) -> str:
    e = html.escape
    total = sum(len(v) for v in groupes.values())
    parties = [
        '<html><body style="font-family:Arial,sans-serif;color:#333;line-height:1.5">',
        '<h2 style="color:#d9534f;border-bottom:2px solid #d9534f">🛡️ Veille Cybersécurité & OSINT Globale</h2>',
        f"<p><b>{total}</b> nouvel(les) actualité(s) et alerte(s) collectées.</p>",
        '<p style="font-size:12px;color:#555">Légende : 🇧🇪 Concerne la Belgique/Wallonie | 🎯 Concerne vos mots-clés suivis</p>'
    ]
    if erreurs:
        parties.append(
            '<p style="background:#fff3cd;padding:8px;border-radius:4px">⚠️ Erreurs de sources : '
            + e(" ; ".join(erreurs))
            + "</p>"
        )
    
    derniere_cat = None
    for source, articles in groupes.items():
        cat_actuelle = articles[0].categorie
        if cat_actuelle != derniere_cat:
            derniere_cat = cat_actuelle
            parties.append(
                '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
                f"{e(derniere_cat)}</h2>"
            )
        parties.append(f'<h3 style="color:#0275d8">{e(source)} ({len(articles)})</h3><ul>')
        for a in articles:
            tag_str = f"<b>{a.tags}</b> " if a.tags else ""
            detail = f"<br><small>{e(a.detail)}</small>" if a.detail else ""
            parties.append(
                f'<li style="margin-bottom:10px">{tag_str}'
                f'<a href="{e(a.lien, quote=True)}" target="_blank">{e(a.titre)}</a>{detail}</li>'
            )
        parties.append("</ul>")
    
    parties.append(
        '<hr><p style="font-size:12px;color:#777">'
        "Généré automatiquement par NourSECBot via GitHub Actions.</p></body></html>"
    )
    return "\n".join(parties)

def envoyer_email(sujet: str, contenu_html: str) -> None:
    expediteur = os.environ["EMAIL_USER"]
    mot_de_passe = os.environ["EMAIL_PASSWORD"]
    destinataire = os.environ["RECIPIENT_EMAIL"]

    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = sujet, expediteur, destinataire
    msg.attach(MIMEText(contenu_html, "html", "utf-8"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as serveur:
        serveur.login(expediteur, mot_de_passe)
        serveur.send_message(msg)
    log.info("E-mail envoyé avec succès.")

def main() -> int:
    deja_vus = charger_deja_vus()
    depuis = datetime.now(timezone.utc) - timedelta(hours=FENETRE_HEURES)
    session = creer_session()

    resultats = [collecter_cisa_kev(session, depuis, deja_vus)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        resultats += list(pool.map(lambda s: collecter_rss(session, s, depuis, deja_vus), SOURCES_RSS))

    erreurs = [err for _, err in resultats if err]
    groupes: dict[str, list[Article]] = {}
    nouveaux_liens = set()

    for articles, _ in resultats:
        if articles:
            groupes[articles[0].source] = articles
            for a in articles:
                nouveaux_liens.add(a.lien)

    groupes = dict(
        sorted(groupes.items(), key=lambda kv: ORDRE_CATEGORIES.index(kv[1][0].categorie))
    )

    if not groupes and not erreurs:
        log.info("Rien de nouveau : pas d'e-mail envoyé.")
        return 0

    sujet = f"🛡️ Veille Cybersécurité du {datetime.now().strftime('%d/%m/%Y')}"
    envoyer_email(sujet, rendre_html(groupes, erreurs))

    deja_vus.update(nouveaux_liens)
    sauvegarder_deja_vus(deja_vus)

    return 0

if __name__ == "__main__":
    sys.exit(main())