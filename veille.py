#!/usr/bin/env python3
"""NourSECBot : veille cybersécurité & OSINT quotidienne envoyée par e-mail."""
from __future__ import annotations

import html
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
from deep_translator import GoogleTranslator
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("noursecbot")

# --- Configuration -----------------------------------------------------------
FENETRE_HEURES = int(os.environ.get("FENETRE_HEURES", "30"))  # ne garder que le récent
MAX_PAR_SOURCE = 10
MAX_CISA = 20
TIMEOUT = 15
# UA de type navigateur : certains sites (Cloudflare) rejettent les User-Agent de bots.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Ordre d'affichage des rubriques dans le mail
ORDRE_CATEGORIES = [
    "Alertes & vulnérabilités",
    "Dark web & ransomware",
    "Actualités cybersécurité",
    "Blogs & OSINT",
]

CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# "langue" : les sources déjà en français ne sont pas traduites.
# Vérifiez régulièrement que chaque URL répond bien (voir les logs / le bandeau d'erreurs).
ALERTES = "Alertes & vulnérabilités"
DARKWEB = "Dark web & ransomware"
ACTUS = "Actualités cybersécurité"
BLOGS = "Blogs & OSINT"

SOURCES_RSS = [
    # --- CERT / autorités ---
    {"nom": "CERT-FR avis", "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
     "langue": "fr", "categorie": ALERTES, "max": 15},
    # URL des alertes CERT-FR à confirmer au premier run (voir bandeau d'erreurs du mail)
    {"nom": "CERT-FR alertes", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
     "langue": "fr", "categorie": ALERTES},
    {"nom": "CERT-FR menaces (CTI)", "url": "https://www.cert.ssi.gouv.fr/cti/feed/",
     "langue": "fr", "categorie": ALERTES},
    {"nom": "CCB Belgique", "url": "https://ccb.belgium.be/advisories.xml",
     "langue": "en", "categorie": ALERTES},
    # --- Dark web : suivi des sites de fuite des groupes de ransomware (via agrégateur public) ---
    {"nom": "Ransomware.live", "url": "https://ransomware.live/cyberattacks.xml",
     "langue": "en", "categorie": DARKWEB},
    # --- Actualités ---
    {"nom": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/",
     "langue": "en", "categorie": ACTUS},
    {"nom": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews",
     "langue": "en", "categorie": ACTUS},
    {"nom": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/",
     "langue": "en", "categorie": ACTUS},
    # --- Blogs & OSINT ---
    {"nom": "Korben", "url": "https://korben.info/feed", "langue": "fr", "categorie": BLOGS},
    {"nom": "Zataz", "url": "https://www.zataz.com/feed/", "langue": "fr", "categorie": BLOGS},
    {"nom": "HackerSploit", "url": "https://hackersploit.org/feed/", "langue": "en", "categorie": BLOGS},
    {"nom": "NetworkChuck", "url": "https://networkchuck.com/feed/", "langue": "en", "categorie": BLOGS},
]


@dataclass
class Article:
    source: str
    titre: str
    lien: str
    date: datetime
    langue: str = "en"
    categorie: str = ALERTES
    detail: str = ""
    alerte: bool = False  # ex. CVE utilisée dans des campagnes de ransomware


# --- Collecte ----------------------------------------------------------------
def creer_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def collecter_rss(session: requests.Session, source: dict, depuis: datetime):
    """Retourne (articles, erreur_ou_None)."""
    try:
        reponse = session.get(source["url"], timeout=TIMEOUT)
        reponse.raise_for_status()
    except requests.RequestException as exc:
        log.warning("%s : %s", source["nom"], exc)
        return [], f"{source['nom']} : {exc}"

    flux = feedparser.parse(reponse.content)
    if flux.bozo and not flux.entries:
        return [], f"{source['nom']} : flux illisible"

    articles = []
    for entree in flux.entries:
        t = entree.get("published_parsed") or entree.get("updated_parsed")
        if not t:
            continue
        date = datetime(*t[:6], tzinfo=timezone.utc)
        if date < depuis:
            continue
        articles.append(
            Article(
                source=source["nom"],
                titre=entree.get("title", "Article sans titre"),
                lien=entree.get("link", source["url"]),
                date=date,
                langue=source["langue"],
                categorie=source["categorie"],
            )
        )
    articles.sort(key=lambda a: a.date, reverse=True)
    log.info("%s : %d article(s) récent(s)", source["nom"], len(articles))
    return articles[: source.get("max", MAX_PAR_SOURCE)], None


def collecter_cisa(session: requests.Session, depuis: datetime):
    try:
        reponse = session.get(CISA_URL, timeout=TIMEOUT)
        reponse.raise_for_status()
        vulns = reponse.json().get("vulnerabilities", [])
    except (requests.RequestException, ValueError) as exc:
        log.warning("CISA : %s", exc)
        return [], f"CISA : {exc}"

    articles = []
    for v in vulns:
        try:
            date = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if date.date() < depuis.date():
            continue
        cve = v.get("cveID", "CVE inconnu")
        articles.append(
            Article(
                source="CISA KEV",
                titre=f"{cve} : {v.get('vendorProject', '?')} {v.get('product', '?')}",
                lien=f"https://nvd.nist.gov/vuln/detail/{cve}",
                date=date,
                detail=v.get("shortDescription", ""),
                categorie=ALERTES,
                alerte=v.get("knownRansomwareCampaignUse") == "Known",
            )
        )
    # Les CVE liées au ransomware d'abord, puis les plus récentes
    articles.sort(key=lambda a: (a.alerte, a.date), reverse=True)
    log.info("CISA : %d vulnérabilité(s) récente(s)", len(articles))
    return articles[:MAX_CISA], None


# --- Traduction --------------------------------------------------------------
def traduire(articles: list[Article]) -> None:
    traducteur = GoogleTranslator(source="auto", target="fr")
    for art in articles:
        if art.langue == "fr":
            continue
        try:
            art.titre = traducteur.translate(art.titre[:500]) or art.titre
            if art.detail:
                art.detail = traducteur.translate(art.detail[:800]) or art.detail
        except Exception as exc:  # deep_translator lève des exceptions variées
            log.warning("Traduction impossible (%s) : on garde l'original", exc)


# --- Rendu -------------------------------------------------------------------
def rendre_html(groupes: dict[str, list[Article]], erreurs: list[str]) -> str:
    e = html.escape
    total = sum(len(v) for v in groupes.values())
    parties = [
        '<html><body style="font-family:Arial,sans-serif;color:#333;line-height:1.5">',
        '<h2 style="color:#d9534f;border-bottom:2px solid #d9534f">'
        "🛡️ Veille cybersécurité & OSINT</h2>",
        f"<p>{total} élément(s) récent(s) sur {len(groupes)} source(s).</p>",
    ]
    if erreurs:
        parties.append(
            '<p style="background:#fff3cd;padding:8px;border-radius:4px">⚠️ Sources en erreur : '
            + e(" ; ".join(erreurs))
            + "</p>"
        )
    derniere_cat = None
    for source, articles in groupes.items():
        if articles[0].categorie != derniere_cat:
            derniere_cat = articles[0].categorie
            parties.append(
                '<h2 style="color:#333;border-bottom:1px solid #ccc;margin-top:28px">'
                f"{e(derniere_cat)}</h2>"
            )
        parties.append(f'<h3 style="color:#0275d8">{e(source)} ({len(articles)})</h3><ul>')
        for a in articles:
            marque = "🔥 " if a.alerte else ""
            detail = f"<br><small>{e(a.detail)}</small>" if a.detail else ""
            parties.append(
                f'<li style="margin-bottom:10px">{marque}'
                f'<a href="{e(a.lien, quote=True)}">{e(a.titre)}</a>{detail}</li>'
            )
        parties.append("</ul>")
    parties.append(
        '<hr><p style="font-size:12px;color:#777">'
        "Généré automatiquement par NourSECBot via GitHub Actions. "
        "🔥 = CVE utilisée dans des campagnes de ransomware.</p></body></html>"
    )
    return "\n".join(parties)


def rendre_texte(groupes: dict[str, list[Article]]) -> str:
    lignes = []
    derniere_cat = None
    for source, articles in groupes.items():
        if articles[0].categorie != derniere_cat:
            derniere_cat = articles[0].categorie
            lignes.append(f"\n##### {derniere_cat.upper()} #####")
        lignes.append(f"\n== {source} ==")
        lignes.extend(f"- {a.titre}\n  {a.lien}" for a in articles)
    return "\n".join(lignes)


# --- Envoi -------------------------------------------------------------------
def envoyer_email(sujet: str, contenu_html: str, contenu_texte: str) -> None:
    try:
        expediteur = os.environ["EMAIL_USER"]
        mot_de_passe = os.environ["EMAIL_PASSWORD"]
        destinataire = os.environ["RECIPIENT_EMAIL"]
    except KeyError as exc:
        raise SystemExit(f"Variable d'environnement manquante : {exc}")

    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = sujet, expediteur, destinataire
    msg.attach(MIMEText(contenu_texte, "plain", "utf-8"))
    msg.attach(MIMEText(contenu_html, "html", "utf-8"))  # le HTML en dernier = préféré

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as serveur:
        serveur.login(expediteur, mot_de_passe)
        serveur.send_message(msg)
    log.info("E-mail envoyé.")


# --- Programme principal -----------------------------------------------------
def main() -> int:
    depuis = datetime.now(timezone.utc) - timedelta(hours=FENETRE_HEURES)
    session = creer_session()

    resultats = [collecter_cisa(session, depuis)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        resultats += list(pool.map(lambda s: collecter_rss(session, s, depuis), SOURCES_RSS))

    erreurs = [err for _, err in resultats if err]
    groupes: dict[str, list[Article]] = {}
    for articles, _ in resultats:
        if articles:
            traduire(articles)
            groupes[articles[0].source] = articles

    groupes = dict(
        sorted(groupes.items(), key=lambda kv: ORDRE_CATEGORIES.index(kv[1][0].categorie))
    )

    if not groupes and not erreurs:
        log.info("Rien de nouveau : pas d'e-mail envoyé.")
        return 0

    sujet = f"🛡️ Veille cybersécurité du {datetime.now().strftime('%d/%m/%Y')}"
    envoyer_email(sujet, rendre_html(groupes, erreurs), rendre_texte(groupes))
    # Code de sortie non nul si TOUTES les sources ont échoué : l'Action apparaît en rouge
    return 1 if not groupes else 0


if __name__ == "__main__":
    sys.exit(main())
