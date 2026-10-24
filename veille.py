#!/usr/bin/env python3
"""NourSECBot : veille cybersécurité & OSINT quotidienne par e-mail."""
from __future__ import annotations
 
import html
import json
import logging
import os
import re
import smtplib
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
 
import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
 
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("noursecbot")
 
# --- Configuration -----------------------------------------------------------
SEEN_FILE = "seen.json"          # commité dans le dépôt par le workflow
SEEN_MAX = 3000                  # nombre maximum de liens mémorisés
FENETRE_HEURES = int(os.environ.get("FENETRE_HEURES", "36"))
CISA_JOURS = int(os.environ.get("CISA_JOURS", "3"))
MAX_PAR_SOURCE = 15
MAX_CISA = 25
TIMEOUT = 15
 
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
 
# Marquage prioritaire (🇧🇪 / 🎯) : correspondance sur mots entiers
MOTS_CLES_BELGIQUE = [
    "belgique", "belgium", "belge", "belges", "wallonie", "bruxelles",
    "securitas", "ccb", "safeonweb",
]
MOTS_CLES_CIBLES = [
    "exchange", "outlook", "node", "ivanti", "vmware", "citrix", "ibm", "vpn", "ransomware",
]
 
 
def _motif(mots: list[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(m) for m in mots) + r")\b", re.IGNORECASE)
 
 
RE_BELGIQUE = _motif(MOTS_CLES_BELGIQUE)
RE_CIBLES = _motif(MOTS_CLES_CIBLES)
 
# --- Filtre de pertinence ------------------------------------------------------
# Appliqué uniquement aux sources généralistes marquées "filtre": True dans SOURCES_RSS.
# Volontairement LARGE (on préfère un article en trop qu'une faille ou une attaque manquée).
# Un article est gardé si son titre, son résumé ou ses catégories contiennent l'un de ces termes.
RE_FILTRE_RACINES = re.compile(
    r"vuln|faille|exploit(?!ation)|zero[- ]?day|0[- ]?day|cyber|hack|pirat|malware|malveill|"
    r"ransom|ran[cç]on|phishing|hame[cç]on|spyware|trojan|cheval de troie|botnet|backdoor|"
    r"porte d[ée]rob|rootkit|ver informatique|virus|stealer|keylogger|ddos|d[ée]ni de service|"
    r"breach|leak|fuite|violation de donn|vol de donn|attack|attaqu|intrusion|compromis|"
    r"compromised|s[ée]cur|correctif|espionn|spying|usurpation|arnaque|scam|fraud|spoof|"
    r"credential|identifiant|mot de passe|password|authenti|chiffrement|encrypt|firewall|"
    r"pare-feu|dark ?web|darknet|sabotage|deepfake|rgpd|gdpr|cnil|pentest|bug bounty",
    re.IGNORECASE,
)
# Termes courts : correspondance sur mots entiers pour éviter les faux positifs
# (ex. "nist" dans "administration", "dos" dans "dossier").
RE_FILTRE_MOTS = _motif([
    "apt", "rce", "xss", "sqli", "csrf", "ssrf", "mfa", "2fa", "ioc", "edr", "vpn",
    "cve", "cert", "cisa", "anssi", "nist", "patch", "patches", "worm", "wiper", "dos", "c2",
])
 
 
def _texte_entree(entree) -> str:
    """Titre + résumé (sans HTML) + catégories de l'article."""
    morceaux = [entree.get("title", ""), entree.get("summary", "")]
    morceaux += [t.get("term", "") for t in entree.get("tags", []) if hasattr(t, "get")]
    brut = " ".join(m for m in morceaux if m)
    return html.unescape(re.sub(r"<[^>]+>", " ", brut))
 
 
def est_pertinent(texte: str) -> bool:
    return bool(RE_FILTRE_RACINES.search(texte) or RE_FILTRE_MOTS.search(texte))
 
ALERTES = "Alertes & vulnérabilités"
DARKWEB = "Dark web & ransomware"
ACTUS = "Actualités & Médias"
INTEL = "Threat Intelligence"
BLOGS = "Blogs & OSINT"
ORDRE_CATEGORIES = [ALERTES, DARKWEB, ACTUS, INTEL, BLOGS]
 
# Une source en erreur n'empêche pas le rapport : elle apparaît dans le bandeau jaune du mail.
SOURCES_RSS = [
    # CERT & autorités
    {"nom": "CERT-FR avis", "url": "https://www.cert.ssi.gouv.fr/avis/feed/", "categorie": ALERTES},
    {"nom": "CERT-FR alertes", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/", "categorie": ALERTES},
    {"nom": "CERT-EU", "url": "https://cert.europa.eu/publications/security-advisories-rss", "categorie": ALERTES},
    {"nom": "Safeonweb (Belgique)", "url": "https://safeonweb.be/fr/rss.xml", "categorie": ALERTES},
    {"nom": "CCB Belgique", "url": "https://ccb.belgium.be/advisories.xml", "categorie": ALERTES},
    {"nom": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "categorie": ALERTES},
    # Dark web / ransomware
    {"nom": "Ransomware.live", "url": "https://ransomware.live/cyberattacks.xml", "categorie": DARKWEB},
    # Actualités & médias
    {"nom": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "categorie": ACTUS},
    {"nom": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "categorie": ACTUS},
    {"nom": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "categorie": ACTUS},
    {"nom": "The Record", "url": "https://therecord.media/feed", "categorie": ACTUS},
    {"nom": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "categorie": ACTUS},
    {"nom": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "categorie": ACTUS},
    {"nom": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "categorie": ACTUS},
    {"nom": "Ars Technica (Security)", "url": "https://arstechnica.com/tag/security/feed/", "categorie": ACTUS, "filtre": True},
    {"nom": "Next", "url": "https://next.ink/feed/", "categorie": ACTUS, "filtre": True},
    # Threat intelligence
    {"nom": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "categorie": INTEL},
    {"nom": "Unit 42 (Palo Alto)", "url": "https://unit42.paloaltonetworks.com/feed/", "categorie": INTEL},
    {"nom": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/", "categorie": INTEL},
    {"nom": "WeLiveSecurity (ESET)", "url": "https://www.welivesecurity.com/feed/", "categorie": INTEL},
    {"nom": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "categorie": INTEL},
    {"nom": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "categorie": INTEL},
    # Blogs & OSINT
    {"nom": "Korben", "url": "https://korben.info/feed", "categorie": BLOGS, "filtre": True},
    {"nom": "Zataz", "url": "https://www.zataz.com/feed/", "categorie": BLOGS},
    {"nom": "HackerSploit", "url": "https://hackersploit.org/feed/", "categorie": BLOGS},
    {"nom": "NetworkChuck", "url": "https://networkchuck.com/feed/", "categorie": BLOGS},
    {"nom": "Bellingcat", "url": "https://www.bellingcat.com/feed/", "categorie": BLOGS},
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
 
 
# --- Mémoire des articles déjà envoyés --------------------------------------
def charger_deja_vus() -> list[str]:
    """Liste ORDONNÉE (du plus ancien au plus récent) : permet de tronquer proprement."""
    try:
        data = json.loads(Path(SEEN_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        log.warning("seen.json illisible (%s) : on repart de zéro", exc)
        return []
    return [str(x) for x in data] if isinstance(data, list) else []
 
 
def sauvegarder_deja_vus(anciens: list[str], nouveaux: list[str]) -> None:
    connus = set(anciens)
    liste = anciens + [lien for lien in nouveaux if lien not in connus]
    try:
        Path(SEEN_FILE).write_text(json.dumps(liste[-SEEN_MAX:], ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        log.warning("Impossible d'écrire %s : %s", SEEN_FILE, exc)
 
 
# --- Collecte ----------------------------------------------------------------
def creer_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT})
    return session
 
 
def analyser_tags(texte: str) -> str:
    marques = []
    if RE_BELGIQUE.search(texte):
        marques.append("🇧🇪")
    if RE_CIBLES.search(texte):
        marques.append("🎯")
    return " ".join(marques)
 
 
def collecter_rss(session: requests.Session, source: dict, depuis: datetime, deja_vus: set[str]):
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
    filtre = source.get("filtre", False)
    ecartes = 0
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
        if filtre and not est_pertinent(_texte_entree(entree)):
            ecartes += 1
            log.info("  écarté (hors-sujet) [%s] : %s", source["nom"], titre)
            continue
        articles.append(
            Article(
                source=source["nom"],
                titre=titre,
                lien=lien,
                date=date,
                categorie=source["categorie"],
                tags=analyser_tags(titre),
            )
        )
    articles.sort(key=lambda a: a.date, reverse=True)
    log.info("%s : %d nouveau(x)%s", source["nom"], len(articles),
             f", {ecartes} écarté(s) hors-sujet" if ecartes else "")
    return articles[: source.get("max", MAX_PAR_SOURCE)], None
 
 
def collecter_cisa_kev(session: requests.Session, deja_vus: set[str]):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        reponse = session.get(url, timeout=TIMEOUT)
        reponse.raise_for_status()
        vulns = reponse.json().get("vulnerabilities", [])
    except (requests.RequestException, ValueError) as exc:
        log.warning("CISA KEV : %s", exc)
        return [], f"CISA KEV : {exc}"
 
    seuil = (datetime.now(timezone.utc) - timedelta(days=CISA_JOURS)).date()
    articles = []
    for v in vulns:
        try:
            date = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if date.date() < seuil:
            continue
        cve = v.get("cveID", "CVE inconnu")
        lien = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if lien in deja_vus:
            continue
        titre = f"{cve} : {v.get('vendorProject', '?')} {v.get('product', '?')}"
        description = v.get("shortDescription", "")
        tags = analyser_tags(f"{titre} {description}")
        if v.get("knownRansomwareCampaignUse") == "Known":
            tags = f"🔥 {tags}".strip()
        articles.append(
            Article(
                source="CISA KEV",
                titre=titre,
                lien=lien,
                date=date,
                categorie=ALERTES,
                detail=description,
                tags=tags,
            )
        )
    # Les CVE liées au ransomware d'abord, puis les plus récentes
    articles.sort(key=lambda a: ("🔥" in a.tags, a.date), reverse=True)
    log.info("CISA KEV : %d nouvelle(s)", len(articles))
    return articles[:MAX_CISA], None
 
 
# --- Rendu -------------------------------------------------------------------
def rendre_html(groupes: dict[str, list[Article]], erreurs: list[str]) -> str:
    e = html.escape
    total = sum(len(v) for v in groupes.values())
    parties = [
        '<html><body style="font-family:Arial,sans-serif;color:#333;line-height:1.5">',
        '<h2 style="color:#d9534f;border-bottom:2px solid #d9534f">🛡️ Cybersecurity Monitoring & OSINT by Nous_Sec_bot</h2>',
        f"<p><b>{total}</b> nouveauté(s) sur {len(groupes)} source(s).</p>",
        '<p style="font-size:12px;color:#555">Légende : 🇧🇪 Belgique/Europe/World · 🎯 vos mots-clés · '
        "🔥 CVE utilisée par des ransomwares</p>",
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
                '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
                f"{e(derniere_cat)}</h2>"
            )
        parties.append(f'<h3 style="color:#0275d8">{e(source)} ({len(articles)})</h3><ul>')
        for a in articles:
            tag = f"<b>{e(a.tags)}</b> " if a.tags else ""
            detail = f"<br><small>{e(a.detail)}</small>" if a.detail else ""
            parties.append(
                f'<li style="margin-bottom:10px">{tag}'
                f'<a href="{e(a.lien, quote=True)}" target="_blank">{e(a.titre)}</a>{detail}</li>'
            )
        parties.append("</ul>")
    parties.append(
        '<hr><p style="font-size:12px;color:#777">'
        "Généré automatiquement par NourSECBot via GitHub Actions.</p></body></html>"
    )
    return "\n".join(parties)
 
 
def rendre_texte(groupes: dict[str, list[Article]], erreurs: list[str]) -> str:
    lignes = []
    if erreurs:
        lignes.append("Sources en erreur : " + " ; ".join(erreurs))
    derniere_cat = None
    for source, articles in groupes.items():
        if articles[0].categorie != derniere_cat:
            derniere_cat = articles[0].categorie
            lignes.append(f"\n##### {derniere_cat.upper()} #####")
        lignes.append(f"\n== {source} ==")
        for a in articles:
            lignes.append(f"- {a.tags + ' ' if a.tags else ''}{a.titre}\n  {a.lien}")
    return "\n".join(lignes)
 
 
# --- Envoi -------------------------------------------------------------------
def verifier_config() -> tuple[str, str, str]:
    manquantes = [k for k in ("EMAIL_USER", "EMAIL_PASSWORD", "RECIPIENT_EMAIL") if not os.environ.get(k)]
    if manquantes:
        raise SystemExit(f"Variable(s) d'environnement manquante(s) : {', '.join(manquantes)}")
    return os.environ["EMAIL_USER"], os.environ["EMAIL_PASSWORD"], os.environ["RECIPIENT_EMAIL"]
 
 
def envoyer_email(config: tuple[str, str, str], sujet: str, contenu_html: str, contenu_texte: str) -> None:
    expediteur, mot_de_passe, destinataire = config
    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = sujet, expediteur, destinataire
    msg.attach(MIMEText(contenu_texte, "plain", "utf-8"))
    msg.attach(MIMEText(contenu_html, "html", "utf-8"))  # le HTML en dernier = version préférée
 
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as serveur:
        serveur.login(expediteur, mot_de_passe)
        serveur.send_message(msg)
    log.info("E-mail envoyé avec succès.")
 
 
# --- Programme principal -----------------------------------------------------
def main() -> int:
    config = verifier_config()  # échoue tout de suite si un secret manque
    anciens = charger_deja_vus()
    deja_vus = set(anciens)
    depuis = datetime.now(timezone.utc) - timedelta(hours=FENETRE_HEURES)
    session = creer_session()
 
    resultats = [collecter_cisa_kev(session, deja_vus)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        resultats += list(pool.map(lambda s: collecter_rss(session, s, depuis, deja_vus), SOURCES_RSS))
 
    erreurs = [err for _, err in resultats if err]
    groupes: dict[str, list[Article]] = {}
    nouveaux: list[str] = []
    vus_ce_run: set[str] = set()
 
    for articles, _ in resultats:
        uniques = []
        for a in articles:
            if a.lien in vus_ce_run:  # même lien publié par deux sources
                continue
            vus_ce_run.add(a.lien)
            uniques.append(a)
            nouveaux.append(a.lien)
        if uniques:
            groupes[uniques[0].source] = uniques
 
    # Tri par rubrique (stable : l'ordre des sources est conservé dans chaque rubrique)
    groupes = dict(sorted(groupes.items(), key=lambda kv: ORDRE_CATEGORIES.index(kv[1][0].categorie)))
 
    if not groupes and not erreurs:
        log.info("Rien de nouveau : pas d'e-mail envoyé.")
        return 0
 
    sujet = f"🛡️ Veille cybersécurité du {datetime.now().strftime('%d/%m/%Y')}"
    envoyer_email(config, sujet, rendre_html(groupes, erreurs), rendre_texte(groupes, erreurs))
 
    # On ne mémorise qu'APRÈS un envoi réussi : si l'envoi échoue, rien n'est perdu.
    sauvegarder_deja_vus(anciens, nouveaux)
 
    # Code de sortie non nul si TOUTES les sources ont échoué : le run apparaît en rouge
    return 1 if not groupes else 0
 
 
if __name__ == "__main__":
    sys.exit(main())
