#!/usr/bin/env python3
"""NourSECBot: daily cyber-security & OSINT watch delivered by e-mail.

Corrected version: per-source isolation, tolerant environment variables,
atomic state writes, KEV cache, EPSS from CSV and a hard e-mail size cap.
"""
from __future__ import annotations

import contextlib
import csv
import gzip
import html
import io
import json
import logging
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.charset import Charset
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo

import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("noursecbot")


def _env_int(name: str, default: int, minimum: int = 1, *legacy: str) -> int:
    """Read an integer from the environment without ever failing the run."""
    for key in (name, *legacy):
        raw = os.environ.get(key, "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            log.warning("%s=%r is not an integer; default: %d", key, raw, default)
            return default
        if value < minimum:
            log.warning("%s=%d < minimum %d; default: %d", key, value, minimum, default)
            return default
        return value
    return default


def _env_bool(name: str, default: bool, *legacy: str) -> bool:
    """Read a loose boolean ("1", "yes", "oui", "on"...) from the environment."""
    for key in (name, *legacy):
        raw = os.environ.get(key, "").strip().lower()
        if raw:
            return raw in {"1", "true", "yes", "oui", "on"}
    return default


def _env_str(name: str, default: str, *legacy: str) -> str:
    """Read a string from the environment, keeping the previous names working."""
    for key in (name, *legacy):
        raw = os.environ.get(key, "").strip()
        if raw:
            return raw
    return default


# --- Configuration -----------------------------------------------------------
SEEN_FILE = "seen.json"          # liens déjà envoyés (commité dans le dépôt par le workflow)
SEEN_MAX = 3000
DB_FILE = "stats.db"             # statistiques historiques SQLite (commité aussi)
DB_RETENTION_DAYS = 400
KEV_CACHE_FILE = "kev_cache.json"  # dernier catalogue KEV réussi (secours hors ligne)

MAX_EMAIL_ARTICLES = _env_int("MAX_EMAIL_ARTICLES", 1000, 20, "MAX_ARTICLES_EMAIL")
# 0 = aucun plafond de taille : le message part complet et Gmail en tronque seulement l'affichage
# (~102 Ko), la suite restant accessible via « Afficher tout le message ». Une valeur > 0 réactive
# la réduction automatique du nombre d'articles.
MAX_EMAIL_BYTES = _env_int("MAX_EMAIL_BYTES", 0, 0)
# base64 = universel (tout serveur SMTP) ; 8bit = ~26 % plus léger mais suppose 8BITMIME (Gmail OK).
EMAIL_ENCODING = _env_str("EMAIL_ENCODING", "base64").lower()

WINDOW_HOURS = _env_int("WINDOW_HOURS", 48, 1, "FENETRE_HEURES")  # 48 h : rapport glissant sur 2 jours
KEV_DAYS = _env_int("KEV_DAYS", 2, 1, "CISA_JOURS")  # 2 : KEV ajoutées sur les 2 derniers jours
MAX_PER_SOURCE = 30

# GitHub abandonne parfois des déclenchements planifiés (documenté « best-effort ») : le workflow
# quotidien est donc planifié plusieurs fois dans la matinée, et cette clé retient la date du
# dernier rapport réellement envoyé, pour ne jamais envoyer deux fois le même jour.
META_DERNIERE_VEILLE = "derniere_veille"
FORCE_VEILLE = _env_bool("FORCE_VEILLE", False)
MAX_KEV = 25
TIMEOUT = 15

TIMEZONE_NAME = _env_str("TZ", "Europe/Brussels")
try:
    TZ = ZoneInfo(TIMEZONE_NAME)
except Exception:  # noqa: BLE001 - tzdata absent sur certaines installations Windows
    log.warning("Time zone %r unavailable: falling back to UTC", TIMEZONE_NAME)
    TZ = timezone.utc

# Priorités du jour
TOP_N = 5
TOP_MAX_KEV = 3                  # au plus 3 places sur 5 pour les entrées CISA KEV
KEV_ALWAYS_CRITICAL = _env_bool("KEV_ALWAYS_CRITICAL", False, "KEV_TOUJOURS_CRITIQUE")

# Rapport glissant : par défaut, on ne filtre plus les liens déjà envoyés.
# Chaque exécution couvre les WINDOW_HOURS dernières heures, même si les
# articles étaient déjà dans le mail de la veille.
IGNORE_SEEN = _env_bool("IGNORE_SEEN", True, "IGNORER_DEJA_VUS")

# Section « Toujours d'actualité » et classement des fournisseurs
REMINDERS_N = 5
REMINDERS_DAYS = 14              # CVE vues pour la 1re fois il y a 1 à 14 jours...
REMINDERS_EPSS_MIN = 0.5         # ... avec EPSS >= 50 %, ou utilisées par des ransomwares
VENDORS_N = _env_int("VENDORS_N", 5, 0)   # 0 = masquer complètement le classement des fournisseurs
VENDORS_DAYS = 30

# Rubriques par pays : nombre d'articles listés par pays, et plafond global.
MAX_ARTICLES_PER_COUNTRY = 6
MAX_COUNTRY_ARTICLES = 45
MAX_COUNTRY_FLAGS = 4            # au-delà, les drapeaux saturent la ligne de titre
MAX_STACK_PER_PRODUCT = 6        # rubrique « ta stack » : articles listés par produit
MAX_STACK_ARTICLES = 24          # ... et au total
SHOW_COUNTRY_LINKS = _env_bool("SHOW_COUNTRY_LINKS", True, "AFFICHER_LIENS_PAYS")

# Rempli par collect_cisa_kev : le catalogue KEV complet sert au classement des fournisseurs
# et à la synchronisation de la base.
KEV_VULNS: list[dict] = []

# Enrichissement (tout est optionnel : sans clé ou en cas d'erreur, le rapport part quand même)
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
MAX_CVSS = _env_int("MAX_CVSS", 30 if NVD_API_KEY else 10, 1)  # NVD : 5 req/30 s sans clé

# SMTP : Gmail par défaut, mais configurable pour un autre fournisseur.
SMTP_HOST = _env_str("SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com"
SMTP_SECURITY = _env_str("SMTP_SECURITY", "ssl", "SMTP_SECURITE").lower()
SMTP_PORT = _env_int("SMTP_PORT", 587 if SMTP_SECURITY == "starttls" else 465, 1)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Types annoncés lors de la lecture d'un flux. Un lecteur RSS les envoie toujours ; certains
# pare-feux refusent un client qui ne déclare rien. Volontairement limité aux appels de flux
# pour ne pas influencer les réponses JSON (NVD, KEV, GitHub).
_FEED_ACCEPT = ("application/rss+xml, application/atom+xml, application/xml;q=0.9, "
                "text/xml;q=0.8, */*;q=0.7")

# Empreinte IBM en Europe : chaque pays où IBM possède une entité ou un bureau.
# Chaque entrée porte les mots-clés qui marquent un article, les liens de l'autorité
# nationale (le CCB pour la Belgique) et un site de sécurité local fiable.
COUNTRIES: dict[str, dict] = {
    "EU": {
        "name": "European Union",
        "flag": "🇪🇺",
        "keywords": [
            "european union", "union européenne", "european commission",
            "commission européenne", "european parliament", "parlement européen",
            "cert-eu", "enisa", "europol", "eurojust", "nato", "eu agency",
            "nis2", "gdpr", "rgpd", "dora", "cyber resilience act", "european",
        ],
        "links": [
            ("CERT-EU", "https://cert.europa.eu/"),
            ("ENISA", "https://www.enisa.europa.eu/"),
            ("NIS2", "https://digital-strategy.ec.europa.eu/en/policies/nis2-directive"),
        ],
    },
    "AT": {
        "name": "Austria",
        "flag": "🇦🇹",
        "keywords": [
            "austria", "autriche", "österreich", "osterreich", "austrian",
            "autrichien", "vienna", "wien",
        ],
        "links": [
            ("CERT.at", "https://www.cert.at/"),
            ("Onlinesicherheit", "https://www.onlinesicherheit.gv.at/"),
        ],
    },
    "BE": {
        "name": "Belgium",
        "flag": "🇧🇪",
        "keywords": [
            "belgium", "belgique", "belgië", "belgie", "belgian", "belge",
            "belges", "brussels", "bruxelles", "brussel", "ccb", "safeonweb",
        ],
        "links": [
            ("CCB", "https://ccb.belgium.be/"),
            ("Safeonweb", "https://safeonweb.be/"),
        ],
    },
    "BG": {
        "name": "Bulgaria",
        "flag": "🇧🇬",
        "keywords": ["bulgaria", "bulgarie", "bulgarian", "bulgare", "sofia"],
        "links": [
            ("GovCERT Bulgaria", "https://www.govcert.bg/"),
        ],
    },
    "HR": {
        "name": "Croatia",
        "flag": "🇭🇷",
        "keywords": ["croatia", "croatie", "croatian", "croate", "zagreb"],
        "links": [
            ("CERT.hr", "https://www.cert.hr/"),
            ("ZSIS", "https://www.zsis.hr/"),
        ],
    },
    "CZ": {
        "name": "Czechia",
        "flag": "🇨🇿",
        "keywords": [
            "czechia", "czech republic", "tchéquie", "république tchèque",
            "czech", "tchèque", "prague", "praha", "brno",
        ],
        "links": [
            ("GovCERT.CZ", "https://www.govcert.cz/"),
            ("NÚKIB", "https://www.nukib.cz/"),
        ],
    },
    "DK": {
        "name": "Denmark",
        "flag": "🇩🇰",
        "keywords": [
            "denmark", "danemark", "danish", "danois", "copenhagen", "københavn",
        ],
        "links": [
            ("CFCS", "https://www.cfcs.dk/"),
            ("Sikkerdigital", "https://www.sikkerdigital.dk/"),
        ],
    },
    "EE": {
        "name": "Estonia",
        "flag": "🇪🇪",
        "keywords": ["estonia", "estonie", "estonian", "estonien", "tallinn"],
        "links": [
            ("CERT-EE", "https://www.cert.ee/"),
            ("RIA", "https://www.ria.ee/"),
        ],
    },
    "FI": {
        "name": "Finland",
        "flag": "🇫🇮",
        "keywords": [
            "finland", "finlande", "finnish", "finlandais", "helsinki",
        ],
        "links": [
            ("NCSC-FI", "https://www.kyberturvallisuuskeskus.fi/en"),
            ("Traficom", "https://www.traficom.fi/en"),
        ],
    },
    "FR": {
        "name": "France",
        "flag": "🇫🇷",
        "keywords": [
            "france", "french", "français", "francais", "paris", "montpellier",
        ],
        "links": [
            ("CERT-FR", "https://www.cert.ssi.gouv.fr/"),
            ("ANSSI", "https://cyber.gouv.fr/"),
        ],
    },
    "DE": {
        "name": "Germany",
        "flag": "🇩🇪",
        "keywords": [
            "germany", "allemagne", "deutschland", "german", "allemand",
            "berlin", "munich", "münchen", "ehningen", "böblingen", "boeblingen",
        ],
        "links": [
            ("BSI", "https://www.bsi.bund.de/"),
            ("CERT-Bund", "https://wid.cert-bund.de/"),
            ("Heise Security", "https://www.heise.de/security/"),
        ],
    },
    "GR": {
        "name": "Greece",
        "flag": "🇬🇷",
        "keywords": ["greece", "grèce", "grece", "greek", "grec", "athens", "athènes"],
        "links": [
            ("GR-CERT (NIS)", "https://www.nis.gr/el/national-cert/"),
        ],
    },
    "HU": {
        "name": "Hungary",
        "flag": "🇭🇺",
        "keywords": ["hungary", "hongrie", "hungarian", "hongrois", "budapest"],
        "links": [
            ("NKI / SZTFH", "https://sztfh.hu/"),
        ],
    },
    "IE": {
        "name": "Ireland",
        "flag": "🇮🇪",
        "keywords": ["ireland", "irlande", "irish", "irlandais", "dublin"],
        "links": [
            ("NCSC Ireland", "https://www.ncsc.gov.ie/"),
        ],
    },
    "IT": {
        "name": "Italy",
        "flag": "🇮🇹",
        "keywords": [
            "italy", "italie", "italian", "italien", "rome", "milan", "milano",
            "segrate",
        ],
        "links": [
            ("CSIRT Italia", "https://www.csirt.gov.it/"),
            ("Cybersecurity360", "https://www.cybersecurity360.it/"),
        ],
    },
    "LV": {
        "name": "Latvia",
        "flag": "🇱🇻",
        "keywords": ["latvia", "lettonie", "latvian", "letton", "riga"],
        "links": [
            ("CERT.LV", "https://cert.lv/"),
        ],
    },
    "LT": {
        "name": "Lithuania",
        "flag": "🇱🇹",
        "keywords": ["lithuania", "lituanie", "lithuanian", "lituanien", "vilnius"],
        "links": [
            ("NKSC", "https://www.nksc.lt/"),
        ],
    },
    "LU": {
        "name": "Luxembourg",
        "flag": "🇱🇺",
        "keywords": ["luxembourg", "luxemburg", "luxembourgish", "luxembourgeois"],
        "links": [
            ("CIRCL", "https://www.circl.lu/"),
            ("NC3", "https://www.nc3.lu/"),
        ],
    },
    "NL": {
        "name": "Netherlands",
        "flag": "🇳🇱",
        "keywords": [
            "netherlands", "nederland", "pays-bas", "holland", "dutch",
            "néerlandais", "amsterdam", "hague", "den haag",
        ],
        "links": [
            ("NCSC-NL", "https://www.ncsc.nl/"),
            ("Security.nl", "https://www.security.nl/"),
        ],
    },
    "NO": {
        "name": "Norway",
        "flag": "🇳🇴",
        "keywords": ["norway", "norvège", "norvege", "norwegian", "norvégien", "oslo"],
        "links": [
            ("NSM", "https://nsm.no/"),
        ],
    },
    "PL": {
        "name": "Poland",
        "flag": "🇵🇱",
        "keywords": [
            "poland", "pologne", "polish", "polonais", "warsaw", "warszawa",
            "kraków", "krakow",
        ],
        "links": [
            ("CERT Polska", "https://cert.pl/"),
            ("Niebezpiecznik", "https://niebezpiecznik.pl/"),
        ],
    },
    "PT": {
        "name": "Portugal",
        "flag": "🇵🇹",
        "keywords": ["portugal", "portuguese", "portugais", "lisbon", "lisbonne", "lisboa"],
        "links": [
            ("CNCS", "https://www.cncs.gov.pt/"),
        ],
    },
    "RO": {
        "name": "Romania",
        "flag": "🇷🇴",
        "keywords": ["romania", "roumanie", "romanian", "roumain", "bucharest", "bucuresti"],
        "links": [
            ("DNSC", "https://dnsc.ro/"),
        ],
    },
    "SK": {
        "name": "Slovakia",
        "flag": "🇸🇰",
        "keywords": ["slovakia", "slovaquie", "slovak", "slovaque", "bratislava"],
        "links": [
            ("SK-CERT", "https://www.sk-cert.sk/"),
        ],
    },
    "SI": {
        "name": "Slovenia",
        "flag": "🇸🇮",
        "keywords": ["slovenia", "slovénie", "slovenie", "slovenian", "slovène", "ljubljana"],
        "links": [
            ("SI-CERT", "https://www.cert.si/"),
        ],
    },
    "ES": {
        "name": "Spain",
        "flag": "🇪🇸",
        "keywords": ["spain", "espagne", "spanish", "espagnol", "madrid", "barcelona"],
        "links": [
            ("INCIBE-CERT", "https://www.incibe.es/"),
            ("CCN-CERT", "https://www.ccn-cert.cni.es/"),
        ],
    },
    "SE": {
        "name": "Sweden",
        "flag": "🇸🇪",
        "keywords": ["sweden", "suède", "suede", "swedish", "suédois", "stockholm"],
        "links": [
            ("CERT-SE", "https://www.cert.se/"),
        ],
    },
    "CH": {
        "name": "Switzerland",
        "flag": "🇨🇭",
        "keywords": [
            "switzerland", "suisse", "schweiz", "svizzera", "swiss", "zurich",
            "zürich",
        ],
        "links": [
            ("NCSC Switzerland", "https://www.ncsc.admin.ch/"),
            ("SWITCH", "https://www.switch.ch/"),
        ],
    },
    "GB": {
        "name": "United Kingdom",
        "flag": "🇬🇧",
        "keywords": [
            "united kingdom", "britain", "great britain", "england", "royaume-uni",
            "british", "britannique", "london", "hursley", "uk",
        ],
        "links": [
            ("NCSC UK", "https://www.ncsc.gov.uk/"),
            ("The Register", "https://www.theregister.com/security/"),
        ],
    },
}

# Ta stack : Box (Cloud + Box Drive), Slack, Microsoft Teams, Outlook.
# « box » et « teams » nus sont trop ambigus en anglais (« black box », « security teams ») :
# ils ne sont retenus que sous forme de locutions, ou encadrés de gardes (voir RE_BOX_BARE).
STACK_PRODUCTS: dict[str, list[str]] = {
    "Box": [
        "box drive", "box.com", "box cloud", "box enterprise", "box shield",
        "box governance", "box platform", "box api", "box ai", "box inc",
    ],
    "Slack": ["slack", "slack connect", "slackbot", "salesforce slack"],
    "Teams": [
        "microsoft teams", "ms teams", "teams app", "teams chat", "teams meeting",
        "teams phone", "teams admin", "teams client",
    ],
    "Outlook": ["outlook", "outlook web app", "outlook.com", "exchange online", "owa"],
    # Parapluie de Outlook et Teams : très bavard, donc filtré par _stack_watch_item().
    "Microsoft 365": ["microsoft 365", "office 365", "m365", "o365"],
}

# Ta stack + les produits critiques les plus exploités (liste inspirée de
# CVE_POC_monitor/known_object.yaml et des vendor advisories).
KEYWORDS_TARGETS = [
    # Microsoft / collaboration
    "microsoft exchange", "exchange", "office 365", "microsoft 365",
    "sharepoint", "entra id", "azure ad", "okta", "saml", "oauth",
    # Virtualisation / réseau / sécurité
    "vmware", "esxi", "vcenter", "citrix", "citrix adc", "netscaler",
    "fortinet", "fortios", "fortigate", "palo alto", "globalprotect",
    "check point", "checkpoint", "ivanti", "ivanti connect secure",
    "ssl-vpn",
    # Produits critiques
    "weblogic", "ofbiz", "geoserver", "tomcat", "confluence", "jenkins",
    "gitlab", "zabbix", "teamcity", "spring security", "solr",
    "apache http server", "dubbo", "coldfusion", "big-ip", "jira",
    "manageengine", "shiro", "harbor", "kafka ui", "moveit", "goanywhere",
    "cleo", "papercut", "solarwinds", "openclaw", "langflow", "n8n",
    "vllm", "cups",
    # ERP / middleware
    "sap netweaver", "sap commerce", "oracle e-business suite",
    "ibm websphere", "ibm maximo", "ibm aspera", "node.js", "nodejs",
    # Matériel et fournisseurs locaux
    "amag", "symmetry", "securitas", "genetec", "voo", "ores",
    "anker", "solix", "tp-link", "tplink",
    # Acces distant d'entreprise : meme famille que Citrix, Ivanti et les SSL-VPN.
    "teamviewer",
]
# Signaux d'exploitation : pondérés plus fort que la simple stack.
KEYWORDS_THREATS = [
    "rce", "remote code execution", "arbitrary code execution", "execute arbitrary code",
    "lpe", "privilege escalation", "privesc",
    "auth bypass", "authentication bypass", "deserialization", "path traversal",
    "command injection", "sql injection", "ssrf", "xxe", "supply chain",
    "dependency confusion", "poc", "proof of concept", "n-day",
    "double extortion", "raas", "initial access broker", "infostealer",
    "exfiltration", "bec", "business email compromise", "quishing",
    "aitm", "evilginx", "token theft", "session hijacking", "mfa fatigue",
    "pass-the-cookie", "golden ticket", "kerberoasting",
]
# Groupes APT / cybercriminels : nom canonique -> alias utilisés par les médias.
ACTORS_MAP = {
    "APT41": ["apt41", "double dragon", "winnti", "barium", "bronze atlas"],
    "APT10": ["apt10", "stone panda", "menupass", "cloud hopper"],
    "APT40": ["apt40", "bronze mohawk", "gadolinium", "temp.periscope"],
    "Volt Typhoon": ["volt typhoon", "bronze silhouette", "vanguard panda"],
    "Salt Typhoon": ["salt typhoon", "ghost emperor", "famoussparrow"],
    "APT31": ["apt31", "zirconium", "judgment panda", "hurricane panda"],
    "APT29": ["apt29", "cozy bear", "midnight blizzard", "nobelium", "the dukes"],
    "APT28": ["apt28", "fancy bear", "forest blizzard", "sofacy", "strontium"],
    "Sandworm": ["sandworm", "seashell blizzard", "voodoo bear", "notpetya"],
    "Turla": ["turla", "uroburos", "venomous bear", "waterbug", "snake malware"],
    "Killnet": ["killnet", "kill net"],
    "Lazarus": ["lazarus", "hidden cobra", "apt38", "zinc"],
    "Kimsuky": ["kimsuky", "thallium", "velvet chollima", "black banshee"],
    "ScarCruft": ["scarcruft", "apt37", "reaper", "group123"],
    "APT33": ["apt33", "elfin", "refined kitten", "holmium"],
    "APT34": ["apt34", "oilrig", "helix kitten", "crambus"],
    "Charming Kitten": ["charming kitten", "apt35", "mint sandstorm", "phosphorus"],
    "MuddyWater": ["muddywater", "mango sandstorm", "mercury", "static kitten"],
    "LockBit": ["lockbit", "lockbit 3", "lockbit black"],
    "ALPHV/BlackCat": ["alphv", "blackcat", "noberus"],
    "Cl0p": ["cl0p", "clop", "ta505"],
    "REvil": ["revil", "sodinokibi", "gold southfield"],
    "Scattered Spider": ["scattered spider", "unc3944", "0ktapus", "muddled libra"],
    "FIN7": ["fin7", "carbanak", "navigator group"],
}
KEYWORDS_ACTORS = [alias for aliases in ACTORS_MAP.values() for alias in aliases]

# MITRE ATT&CK : identifiant -> termes de détection. Sert à l'affichage (et non au score,
# pour ne pas doubler avec KEYWORDS_THREATS).
TTP_MAP = {
    "T1566": ["phishing", "spear-phishing", "spearphish", "hameçonnage"],
    "T1190": ["exploit public-facing", "rce", "remote code execution", "sql injection", "sqli"],
    "T1195": ["supply chain", "dependency confusion", "third-party"],
    "T1078": ["credential stuffing", "password spray", "account takeover", "valid accounts"],
    "T1003": ["mimikatz", "lsass", "credential dump", "ntlm hash"],
    "T1055": ["process injection", "dll injection", "hollowing", "reflective"],
    "T1071": ["cobalt strike", "beaconing", "command and control", "c2"],
    "T1486": ["ransomware", "lockbit", "blackcat", "alphv", "clop", "rançongiciel"],
    "T1498": ["ddos", "denial of service", "botnet attack"],
    "T1485": ["wiper", "data destruction", "disk wipe", "destructive"],
}
# Volontairement absents : "windows", "linux", "teams", "azure" (présents dans trop d'articles,
# le marqueur 🎯 perdrait son sens), et "ransomware" (déjà pondéré par RE_RANSOM et signalé par 🔥 :
# sinon chaque entrée Ransomware.live recevrait aussi 🎯 et un double comptage).


def _pattern(words: list[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)


RE_COUNTRIES = {code: _pattern(info["keywords"]) for code, info in COUNTRIES.items()}
RE_TARGETS = _pattern(KEYWORDS_TARGETS)
RE_THREATS = _pattern(KEYWORDS_THREATS)
RE_ACTORS = _pattern(KEYWORDS_ACTORS)
RE_ACTORS_MAP = {name: _pattern(aliases) for name, aliases in ACTORS_MAP.items()}
RE_TTP_MAP = {tid: _pattern(terms) for tid, terms in TTP_MAP.items()}
RE_STACK = {name: _pattern(words) for name, words in STACK_PRODUCTS.items()}
# « box » nu : refusé après « black » et devant « office / model / set / cutter / plot / art ».
RE_BOX_BARE = re.compile(
    r"(?<!black )\bbox\b(?!\s?(?:office|model|set|cutter|plot|art)\b)", re.IGNORECASE)


def detect_actors(text: str) -> tuple[str, ...]:
    return tuple(name for name, pattern in RE_ACTORS_MAP.items() if pattern.search(text))


def detect_ttps(text: str) -> tuple[str, ...]:
    return tuple(tid for tid, pattern in RE_TTP_MAP.items() if pattern.search(text))


def detect_countries(text: str) -> tuple[str, ...]:
    """Pays de l'empreinte IBM cités dans le texte, dans l'ordre de COUNTRIES."""
    return tuple(code for code, pattern in RE_COUNTRIES.items() if pattern.search(text))


# Etudes de marche (« Cybersecurity Outlook 2027 », « Threat Outlook ») : « outlook » y designe un
# pronostic, pas le client mail. On neutralise ces tournures avant la detection de stack.
RE_STACK_NOISE = re.compile(
    r"\b(?:cyber\s?security|security|threats?|technology|industry|market|it|ransomware|risk)"
    r"\s+outlook\b"
    r"|\boutlook\s+20\d\d\b",
    re.IGNORECASE,
)


def detect_stack(text: str) -> tuple[str, ...]:
    """Produits de ta stack cités dans le texte (Box, Slack, Teams, Outlook)."""
    text = RE_STACK_NOISE.sub(" ", text)
    found = [name for name, pattern in RE_STACK.items() if pattern.search(text)]
    if "Box" not in found and RE_BOX_BARE.search(text):
        found.insert(0, "Box")
    return tuple(found)

# --- Score de criticité --------------------------------------------------------
CRITICAL_THRESHOLD = 10    # 🔴
IMPORTANT_THRESHOLD = 5    # 🟠 ; en dessous : aucune pastille (une pastille verte laisserait croire "sans danger")

# Pays de proximite immediate : Benelux et France, la ou se trouve le siege. Une mention de ces
# pays pese plus lourd que le reste de l'empreinte IBM, victimes ransomware comprises.
HOME_COUNTRIES = ("BE", "LU", "NL", "FR")
# Abaisse de 6 a 5 apres mesure sur 1346 articles reels : une CVE sur un produit suivi vaut deja
# 5 (3 + 2), et ces articles ressortaient sans marque. Effet : 143 -> 176 pastilles (11 % -> 13 %).

# Identifiant CVE : au moins 4 chiffres à la fin (format officiel). Les médias écrivent parfois
# le tiret avec un caractère typographique (‐ ‑ ‒ – — −) : on l'accepte et on le normalise.
_HYPHEN = r"[-\u2010-\u2015\u2212]"
RE_CVE = re.compile(rf"CVE{_HYPHEN}\d{{4}}{_HYPHEN}\d{{4,}}", re.IGNORECASE)
RE_TYPO_HYPHENS = re.compile(r"[\u2010-\u2015\u2212]")
RE_ZERO_DAY = re.compile(r"\b(?:zero[- ]?days?|0[- ]?days?)\b|jour[- ]z[ée]ro", re.IGNORECASE)
RE_RANSOM = re.compile(r"ransomware|ran[cç]ongiciel", re.IGNORECASE)
# « in the wild » nu était trop large : « not exploited in the wild » prenait +5.
# Les \b évitent aussi « inexploitée » et « inactive exploitation ».
RE_EXPLOITED = re.compile(
    r"\bactively exploited|\bactive(?:ly)? exploit|\bexploited in (?:the wild|attacks)|"
    r"\bexploitation (?:active|dans la nature)|\bactivement exploit|"
    r"\bexploit[ée]e?s? (?:activement|dans la nature)",
    re.IGNORECASE,
)
# Campagne active (⚡) : volontairement sans "campaign" ni "widespread" seuls ("phishing campaign"
# apparaît tous les jours). On garde des expressions qui impliquent une exploitation en cours.
RE_CAMPAIGN = re.compile(
    r"mass[- ]exploitation|exploitation (?:massive|de masse)|attack wave|vague d.attaques|"
    r"botnet|mirai|(?:scan|scanning) activity|widespread (?:exploitation|attacks?)|"
    r"(?:ongoing|active|large[- ]scale|massive) (?:attack )?campaign|"
    r"campagne (?:active|en cours|massive)",
    re.IGNORECASE,
)

# Négation immédiate : « not exploited », « aucune exploitation », « pas de ransomware »...
RE_NEGATION = re.compile(
    r"\b(?:not(?!\s+(?:only|just))|no|never|aucun(?:e)?|"
    r"pas(?!\s+(?:seulement|uniquement))|sans|non(?!\s+seulement))"
    r"\s+(?:\w+\s+){0,4}$",
    re.IGNORECASE,
)


def _positive(pattern: re.Pattern, text: str) -> bool:
    """Vrai si au moins une occurrence du motif n'est pas immédiatement niée."""
    for m in pattern.finditer(text):
        before = text[max(0, m.start() - 60):m.start()]
        if not RE_NEGATION.search(before):
            return True
    return False


def severity_badge(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "🔴"
    if score >= IMPORTANT_THRESHOLD:
        return "🟠"
    return ""


# Fuites de donnees : categorie a part entiere, distincte des vulnerabilites. Sans ces motifs, un
# vol de plusieurs millions de comptes ne declenchait rien du tout (score 0 sur des titres reels).
RE_BREACH = re.compile(
    r"\b(?:"
    r"data\s+breach"
    r"|(?:data|records|customers?|accounts?|patients?|credentials?)\s+(?:breached|leaked|exposed|stolen)"
    r"|breach(?:ed)?\s+(?:data|records|accounts|customers)"
    r"|leak(?:ed|s)?\s+(?:data|database|credentials|records|source\s+code)"
    r"|(?:data|database)\s+leak"
    r"|records\s+exposed"
    r"|(?:key|keys|token|tokens|password|passwords|secret|secrets)\s+(?:leaked|exposed|stolen)"
    r"|millions?\s+of\s+(?:records|accounts|customers|users)"
    r"|fuite\s+de\s+donn\w*"
    r")\b",
    re.IGNORECASE,
)

# L'echelle est ce qui separe une fuite ordinaire d'un incident majeur.
RE_BREACH_SCALE = re.compile(
    r"\b(?:"
    r"\d[\d.,\s]*\s*(?:million|milliard|thousand)\b"
    r"|millions?|milliards?|billions?"
    r"|(?:records|patients|accounts|customers|comptes|utilisateurs)\b"
    r")",
    re.IGNORECASE,
)


# Identifiants debloques : au moins aussi grave qu'une fuite massive de donnees personnelles.
RE_CRED_LEAK = re.compile(
    r"\b(?:master\s+key|api\s+key|private\s+key|credentials?|tokens?|passwords?)"
    r"\s+(?:leaked|exposed|stolen)",
    re.IGNORECASE,
)


def _breach_bonus(text: str) -> int:
    """+5 pour une fuite, +3 de plus si des personnes sont touchees ou des identifiants debloques.
    Plafond volontaire a 8 : une fuite ne doit jamais suffire a declencher l'alerte immediate,
    qui reste reservee aux exploitations."""
    if not RE_BREACH.search(text):
        return 0
    if RE_BREACH_SCALE.search(text) or RE_CRED_LEAK.search(text):
        return 8
    return 5


# Impact de masse : un titre sans CVE qui annonce des millions de machines touchees n'est pas un
# article anodin. Volontairement modeste (+3) pour ne pas confondre avec du marketing.
RE_MASS_IMPACT = re.compile(
    r"\b(?:millions?|thousands?|centaines de milliers)\s+"
    r"(?:of\s+)?(?:sites?|servers?|devices?|users?|machines?|routers?|organi[sz]ations?|sites web)\b",
    re.IGNORECASE,
)


def compute_criticality(text: str) -> tuple[int, str]:
    score = 0
    if RE_CVE.search(text):
        score += 3
    if _positive(RE_ZERO_DAY, text):
        score += 4
    if _positive(RE_RANSOM, text):
        score += 3
    if _positive(RE_EXPLOITED, text):
        # 6 et non 5 : « exploite activement » suffit a meriter une pastille a lui seul. A 5, ces
        # titres tombaient un point sous le seuil et ressortaient sans marque (constate sur 7
        # articles reels : PHP2Shell, Drupal, ASA/FTD, VeloCloud).
        score += 6
    score += _breach_bonus(text)
    if RE_MASS_IMPACT.search(text):
        score += 3
    if _positive(RE_CAMPAIGN, text):
        score += 3
    if _positive(RE_THREATS, text):
        score += 3
    if RE_ACTORS.search(text):
        score += 2
    countries = detect_countries(text)
    if countries:
        # Benelux et France pesent plus lourd qu'une simple mention d'un autre pays de l'empreinte,
        # et l'UE est traitee comme le siege : elle reste au niveau haut.
        if any(c in HOME_COUNTRIES for c in countries) or "EU" in countries:
            score += 3
        else:
            score += 1
    if detect_stack(text):
        score += 2   # un article qui concerne directement ta stack pèse plus lourd
    if RE_TARGETS.search(text):
        score += 2
    return score, severity_badge(score)


def enrichment_bonus(epss: float | None, cvss: float | None) -> int:
    """Points ajoutés une fois EPSS (probabilité d'exploitation) et CVSS (gravité) connus."""
    bonus = 0
    if epss is not None:
        if epss >= 0.5:
            bonus += 4
        elif epss >= 0.1:
            bonus += 2
    if cvss is not None:
        if cvss >= 9.0:
            bonus += 2
        elif cvss >= 7.0:
            bonus += 1
    return bonus


def extract_cves(text: str) -> set[str]:
    """CVE distinctes, normalisées (tiret ASCII, majuscules)."""
    return {RE_TYPO_HYPHENS.sub("-", m).upper() for m in RE_CVE.findall(text)}


# --- Filtre de pertinence ------------------------------------------------------
# Appliqué uniquement aux sources généralistes marquées "filter": True dans RSS_SOURCES.
# Volontairement LARGE (on préfère un article en trop qu'une faille ou une attaque manquée).
# Un article est gardé si son titre, son résumé ou ses catégories contiennent l'un de ces termes.
RE_FILTER_ROOTS = re.compile(
    r"vuln|faille|flaw|exploit(?!ation)|zero[- ]?day|0[- ]?day|cyber|hack|pirat|malware|malveill|"
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
RE_FILTER_WORDS = _pattern([
    "apt", "rce", "xss", "sqli", "csrf", "ssrf", "mfa", "2fa", "ioc", "edr", "vpn",
    "cve", "cert", "cisa", "anssi", "nist", "patch", "patches", "worm", "wiper", "dos", "c2",
])


def _entry_text(entry) -> str:
    """Titre + résumé (sans HTML) + contenu + catégories de l'article."""
    parts = [entry.get("title") or "", entry.get("summary") or ""]
    for block in entry.get("content") or []:
        if isinstance(block, dict):
            parts.append(block.get("value") or "")
    parts += [t.get("term", "") for t in (entry.get("tags") or []) if hasattr(t, "get")]
    raw = " ".join(p for p in parts if p)
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))[:20_000]


def _short_text(entry) -> str:
    """Titre + résumé + catégories (sans le corps complet) : base du scoring et des CVE.

    Un article long qui cite 15 vieilles CVE ou mentionne « ransomware » en passant
    ne doit pas passer 🔴 ; le filtre de pertinence, lui, garde le texte complet.
    """
    parts = [entry.get("title") or "", entry.get("summary") or ""]
    parts += [t.get("term", "") for t in (entry.get("tags") or []) if hasattr(t, "get")]
    raw = " ".join(p for p in parts if p)
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))[:3_000]


def is_relevant(text: str) -> bool:
    return bool(RE_FILTER_ROOTS.search(text) or RE_FILTER_WORDS.search(text))


# Traduction locale des avis BSI : leurs titres suivent une formule fixe (« [NEU] [hoch] Produit :
# Schwachstelle ermöglicht … »), donc un simple remplacement de locutions suffit. Aucune API, aucun
# quota, aucune dépendance — et le nom du produit reste intact. Les locutions longues passent en
# premier pour ne pas être tronquées par une plus courte.
_DE_EN = {
    "[NEU]": "[NEW]", "[UPDATE]": "[UPDATED]", "[UNGEPATCHT]": "[UNPATCHED]",
    "[kritisch]": "[critical]", "[hoch]": "[high]",
    "[mittel]": "[medium]", "[niedrig]": "[low]",
    "Mehrere Schwachstellen ermöglichen": "Multiple vulnerabilities allow",
    "Mehrere Schwachstellen": "Multiple vulnerabilities",
    "Schwachstelle ermöglicht": "Vulnerability allows",
    "Schwachstelle in": "Vulnerability in",
    "Offenlegung von Informationen": "disclosure of information",
    "Preisgabe von Informationen": "exposure of information",
    "Umgehen von Sicherheitsvorkehrungen": "bypass of security controls",
    "Ausführen von beliebigem Code": "arbitrary code execution",
    "beliebigen Code ausführen": "execute arbitrary code",
    "Privilegieneskalation": "privilege escalation",
    "Sicherheitsvorkehrungen": "security controls",
    "Cross-Site-Scripting": "cross-site scripting",
    "Schwachstellen": "vulnerabilities",
    "Schwachstelle": "vulnerability",
    "Sicherheitslücke": "security flaw",
    "Denial of Service": "denial of service",
    "Manipulation von Dateien": "file manipulation",
    "Angreifer": "attackers",
    "ermöglicht": "allows",
    "Umgehen": "bypass",
    # Connecteurs, avec espaces pour ne pas casser un nom de produit (« Juniper und Cisco »).
    " und ": " and ",
    " für ": " for ",
    " mit ": " with ",
}
_DE_TERMS = tuple(sorted(_DE_EN.items(), key=lambda kv: -len(kv[0])))


def translate_german(title: str) -> str:
    """Traduit les locutions allemandes d'un titre d'avis, sans toucher au nom du produit."""
    for de, en in _DE_TERMS:
        if de in title:
            title = title.replace(de, en)
    return title


ALERTS = "Alerts & Vulnerabilities"
DARKWEB = "Dark web & Ransomware"
NEWS = "News & Media"
INTEL = "Threat Intelligence"
BLOGS = "Blogs & OSINT"
CATEGORY_ORDER = [ALERTS, DARKWEB, NEWS, INTEL, BLOGS]
SOURCE_RANSOMWARE_LIVE = "Ransomware.live"
SOURCE_KEV = "CISA KEV"
SOURCE_GITHUB = "GitHub Advisory"
SOURCE_RANSOMWARE_API = "Ransomware.live (victims)"
# Cle facultative de l'API PRO (gratuite). Sans elle, le collecteur utilise l'acces anonyme.
RANSOMWARE_API_KEY = _env_str("RANSOMWARE_API_KEY", "")

# Sources hors flux RSS, collectées par du code dédié : CISA KEV et GitHub Advisory.
EXTRA_SOURCES = 2
# Pistes API non câblées ici car elles ne produisent pas des articles RSS :
# CIRCL CVE Search (JSON CVE), Feodo Tracker (IP de C2), GitHub Search (PoC).
# GitHub Advisory, lui, est branché dans collect_github_advisories().

# Une source en erreur n'empêche pas le rapport : elle apparaît dans le bandeau jaune du mail.
RSS_SOURCES = [
    # CERT & autorités
    {"name": "CERT-FR avis", "url": "https://www.cert.ssi.gouv.fr/avis/feed/", "category": ALERTS, "country": "FR"},
    {"name": "CERT-FR alertes", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/", "category": ALERTS, "country": "FR"},
    {"name": "CERT-EU", "url": "https://cert.europa.eu/publications/security-advisories-rss", "category": ALERTS, "country": "EU"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": ALERTS},
    {"name": "NCSC UK", "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "category": ALERTS, "country": "GB"},
    {"name": "JPCERT/CC", "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", "category": ALERTS},
    {"name": "CERT/CC", "url": "https://kb.cert.org/vuls/atomfeed/", "category": ALERTS},
    {"name": "Safeonweb (Belgique)", "url": "https://safeonweb.be/fr/rss.xml", "category": ALERTS, "country": "BE"},
    {"name": "CCB Belgique", "url": "https://ccb.belgium.be/advisories.xml", "category": ALERTS, "country": "BE"},
    {"name": "NCSC-NL", "url": "https://advisories.ncsc.nl/rss/advisories", "category": ALERTS, "country": "NL"},
    {"name": "CERT Polska", "url": "https://cert.pl/feed/", "category": ALERTS, "country": "PL"},
    {"name": "BSI CERT-Bund", "url": "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "category": ALERTS, "country": "DE", "translate": True, "max": 30},
    {"name": "CERT-SE", "url": "https://www.cert.se/feed", "category": ALERTS, "country": "SE"},
    {"name": "CERT.hr", "url": "https://www.cert.hr/feed/", "category": ALERTS, "country": "HR"},
    {"name": "SI-CERT", "url": "https://www.cert.si/feed/", "category": ALERTS, "country": "SI"},
    {"name": "Full Disclosure", "url": "https://seclists.org/rss/fulldisclosure.rss", "category": ALERTS},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "category": ALERTS},
    # Vulnérabilités / exploits / avis fournisseurs
    {"name": "FortiGuard PSIRT", "url": "https://www.fortiguard.com/rss/ir.xml", "category": ALERTS},
    {"name": "Microsoft MSRC", "url": "https://api.msrc.microsoft.com/update-guide/rss", "category": ALERTS, "max": 10},
    {"name": "Palo Alto Advisories", "url": "https://security.paloaltonetworks.com/rss.xml", "category": ALERTS},
    {"name": "Cisco PSIRT", "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "category": ALERTS},
    {"name": "oss-security", "url": "https://seclists.org/rss/oss-sec.rss", "category": ALERTS, "filter": True},
    {"name": "Chrome Releases", "url": "https://chromereleases.googleblog.com/feeds/posts/default", "category": ALERTS, "filter": True, "max": 5},
    {"name": "CVEfeed", "url": "https://cvefeed.io/rssfeed/latest.xml", "category": ALERTS, "max": 5},
    {"name": "Zero Day Initiative", "url": "https://www.zerodayinitiative.com/rss/published/", "category": ALERTS},
    {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": ALERTS},
    # Dark web / ransomware
    {"name": SOURCE_RANSOMWARE_LIVE, "url": "https://ransomware.live/cyberattacks.xml", "category": DARKWEB},
    # RansomLook (CC BY 4.0) : agrege les blogs de groupes, forums et canaux Telegram publics.
    {"name": "RansomLook", "url": "https://www.ransomlook.io/rss.xml", "category": DARKWEB},
    # Flux thématisés : ils sont collectés avant les flux généralistes des mêmes sites, donc
    # l'article ransomware est rattaché à cette rubrique et le doublon est écarté plus loin.
    {"name": "Help Net Security (Ransomware)", "url": "https://www.helpnetsecurity.com/tag/ransomware/feed/", "category": DARKWEB},
    {"name": "CyberScoop (Ransomware)", "url": "https://cyberscoop.com/tag/ransomware/feed/", "category": DARKWEB},
    {"name": "The Record (Ransomware)", "url": "https://therecord.media/feed?tag=ransomware", "category": DARKWEB},
    {"name": "FrenchBreaches", "url": "https://frenchbreaches.com/feed.xml", "category": DARKWEB, "country": "FR"},
    {"name": "Databreaches.net", "url": "https://databreaches.net/feed/", "category": DARKWEB},
    # Actualités & médias
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": NEWS},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": NEWS},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": NEWS},
    {"name": "The Record", "url": "https://therecord.media/feed", "category": NEWS},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "category": NEWS},
    # Dark Reading ne publie plus de flux par rubrique (tous en 404) : le flux global est filtre
    # sur les mots-cles pour ecarter les sujets carriere/gouvernance, comme le faisait la rubrique.
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "category": NEWS, "filter": True},
    {"name": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "category": NEWS},
    {"name": "CyberScoop", "url": "https://cyberscoop.com/feed/", "category": NEWS},
    {"name": "Security Affairs", "url": "https://securityaffairs.com/feed", "category": NEWS},
    {"name": "Wired Security", "url": "https://www.wired.com/feed/category/security/latest/rss", "category": NEWS},
    {"name": "CSO Online", "url": "https://www.csoonline.com/feed/", "category": NEWS},
    {"name": "UnderNews", "url": "https://www.undernews.fr/feed", "category": NEWS},
    {"name": "Le Monde Informatique Sécurité", "url": "https://www.lemondeinformatique.fr/flux-rss/thematique/securite/rss.xml", "category": NEWS},
    {"name": "IT-Connect", "url": "https://www.it-connect.fr/feed/", "category": NEWS, "filter": True},
    {"name": "01net", "url": "https://www.01net.com/rss/info/flux-rss/flux-toutes-les-actualites/", "category": NEWS, "filter": True, "max": 5},
    {"name": "Clubic", "url": "https://www.clubic.com/feed/news.rss", "category": NEWS, "filter": True, "max": 5},
    {"name": "Ars Technica (Security)", "url": "https://arstechnica.com/tag/security/feed/", "category": NEWS, "filter": True},
    {"name": "Next", "url": "https://next.ink/feed/", "category": NEWS, "filter": True, "max": 5},
    {"name": "TechCrunch (Security)", "url": "https://techcrunch.com/tag/cybersecurity/feed/", "category": NEWS, "filter": True, "max": 5},
    {"name": "Graham Cluley", "url": "https://www.grahamcluley.com/feed/", "category": NEWS},
    {"name": "Security.nl", "url": "https://www.security.nl/rss/headlines.xml", "category": NEWS, "country": "NL"},
    {"name": "The Register", "url": "https://www.theregister.com/headlines.atom", "category": NEWS},
    {"name": "Infosecurity Magazine", "url": "https://www.infosecurity-magazine.com/rss/news/", "category": NEWS},
    # Threat intelligence / recherche
    {"name": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "category": INTEL},
    {"name": "Unit 42 (Palo Alto)", "url": "https://unit42.paloaltonetworks.com/feed/", "category": INTEL},
    {"name": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/", "category": INTEL},
    {"name": "Sekoia", "url": "https://blog.sekoia.io/feed/", "category": INTEL},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/", "category": INTEL},
    {"name": "Rapid7", "url": "https://www.rapid7.com/blog/rss/", "category": INTEL},
    {"name": "Proofpoint", "url": "https://www.proofpoint.com/us/threat-insight-blog.xml", "category": INTEL},
    {"name": "Group-IB", "url": "https://www.group-ib.com/blog/feed/", "category": INTEL},
    {"name": "Wiz", "url": "https://www.wiz.io/feed/rss.xml", "category": INTEL},
    {"name": "ReversingLabs", "url": "https://www.reversinglabs.com/blog/rss.xml", "category": INTEL},
    {"name": "watchTowr Labs", "url": "https://labs.watchtowr.com/rss/", "category": INTEL},
    {"name": "WeLiveSecurity (ESET)", "url": "https://www.welivesecurity.com/feed/", "category": INTEL},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "category": INTEL},
    {"name": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "category": INTEL},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/", "category": INTEL},
    {"name": "SentinelOne Labs", "url": "https://labs.sentinelone.com/feed/", "category": INTEL},
    {"name": "Elastic Security Labs", "url": "https://www.elastic.co/security-labs/rss/feed.xml", "category": INTEL},
    {"name": "Recorded Future", "url": "https://www.recordedfuture.com/feed/", "category": INTEL},
    {"name": "Red Canary", "url": "https://www.redcanary.com/blog/feed/", "category": INTEL},
    {"name": "GreyNoise", "url": "https://www.greynoise.io/blog/rss.xml", "category": INTEL},
    {"name": "Citizen Lab", "url": "https://citizenlab.org/category/lab-news/feed/", "category": INTEL},
    {"name": "Google Cloud Threat Intelligence", "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "category": INTEL},
    {"name": "CrowdStrike", "url": "https://www.crowdstrike.com/en-us/blog/feed", "category": INTEL},
    {"name": "Volexity", "url": "https://www.volexity.com/feed/", "category": INTEL},
    {"name": "NVISO Labs", "url": "https://blog.nviso.eu/feed/", "category": INTEL, "country": "BE"},
    {"name": "Horizon3.ai", "url": "https://www.horizon3.ai/feed/", "category": INTEL},
    {"name": "PortSwigger Research", "url": "https://portswigger.net/research/rss", "category": INTEL},
    {"name": "Hackmageddon", "url": "https://www.hackmageddon.com/feed/", "category": INTEL},
    # Blogs & OSINT
    {"name": "Korben", "url": "https://korben.info/feed", "category": BLOGS, "filter": True},
    {"name": "Zataz", "url": "https://www.zataz.com/feed/", "category": BLOGS},
    {"name": "HackerSploit", "url": "https://hackersploit.org/feed/", "category": BLOGS},
    {"name": "NetworkChuck", "url": "https://networkchuck.com/feed/", "category": BLOGS},
    {"name": "Bellingcat", "url": "https://www.bellingcat.com/feed/", "category": BLOGS},
    {"name": "Risky Business", "url": "https://risky.biz/feeds/risky-business/", "category": BLOGS},
    {"name": "Troy Hunt", "url": "https://www.troyhunt.com/rss/", "category": BLOGS},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "category": BLOGS},
    {"name": "DoublePulsar", "url": "https://doublepulsar.com/feed", "category": BLOGS},
    {"name": "Pen Test Partners", "url": "https://www.pentestpartners.com/feed/", "category": BLOGS},
]

# Lien affiché derrière le nom d'une source : la racine de son site, jamais son flux RSS — ouvrir
# du XML n'aurait aucun intérêt à l'écran.
_SITE_ALIASES = {"feeds.feedburner.com": "https://thehackernews.com/",
                 "wid.cert-bund.de": "https://www.bsi.bund.de/"}


def _site_root(url: str) -> str:
    host = urlsplit(url).netloc
    if host in _SITE_ALIASES:
        return _SITE_ALIASES[host]
    return f"https://{host}/" if host else url


SOURCE_LINKS: dict[str, str] = {s["name"]: _site_root(s["url"]) for s in RSS_SOURCES}
SOURCE_LINKS[SOURCE_KEV] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
SOURCE_LINKS[SOURCE_GITHUB] = "https://github.com/advisories"

# Pondération des sources (idée reprise de CyberWatch) : 3 = autorité, 2 = recherche,
# 1 = actualité, 0 = blog/OSINT. Le score final est ajusté dans collect_rss.
SOURCE_WEIGHTS = {
    "CERT-FR avis": 3, "CERT-FR alertes": 3, "CERT-EU": 3, "CISA Advisories": 3,
    "NCSC UK": 3, "JPCERT/CC": 3, "CCB Belgique": 3,
    "CERT/CC": 3,
    "NCSC-NL": 3, "CERT Polska": 3,
    "BSI CERT-Bund": 3, "CERT-SE": 3, "CERT.hr": 3, "SI-CERT": 3, "Full Disclosure": 2,
    "Safeonweb (Belgique)": 2, "SANS ISC Diary": 2,
    "FortiGuard PSIRT": 3, "Microsoft MSRC": 3, "Palo Alto Advisories": 3,
    "Cisco PSIRT": 3, "oss-security": 2, "Chrome Releases": 2,
    "CVEfeed": 2, "Zero Day Initiative": 3, "Exploit-DB": 2,
    "Ransomware.live": 1, "Help Net Security (Ransomware)": 1,
    "Ransomware.live (victims)": 2,
    "RansomLook": 2,
    "CyberScoop (Ransomware)": 2, "The Record (Ransomware)": 2, "FrenchBreaches": 2,
    "Databreaches.net": 2,
    "GitHub Advisory": 3,
    "BleepingComputer": 1, "The Hacker News": 1, "Krebs on Security": 2,
    "The Record": 2, "SecurityWeek": 1, "Dark Reading": 2, "Help Net Security": 1,
    "CyberScoop": 2, "Security Affairs": 1, "Wired Security": 1,
    "CSO Online": 1, "UnderNews": 1,
    "Le Monde Informatique Sécurité": 1, "IT-Connect": 1, "01net": 0, "Clubic": 0,
    "Ars Technica (Security)": 1, "Next": 1, "TechCrunch (Security)": 1,
    "Graham Cluley": 2, "Security.nl": 1, "The Register": 2,
    "Infosecurity Magazine": 1,
    "Google Project Zero": 3, "Unit 42 (Palo Alto)": 3, "Securelist (Kaspersky)": 2,
    "WeLiveSecurity (ESET)": 2, "Cisco Talos": 3, "Microsoft Security": 2,
    "The DFIR Report": 3, "SentinelOne Labs": 2,
    "Check Point Research": 3, "Rapid7": 2, "Proofpoint": 3,
    "Group-IB": 3, "Wiz": 2, "ReversingLabs": 2, "watchTowr Labs": 3,
    "Google Cloud Threat Intelligence": 3, "CrowdStrike": 2, "Volexity": 3,
    "NVISO Labs": 2, "Horizon3.ai": 2, "PortSwigger Research": 1, "Hackmageddon": 1,
    "Elastic Security Labs": 2, "Sekoia": 2, "Recorded Future": 2,
    "Red Canary": 2, "GreyNoise": 2, "Citizen Lab": 2,
    "Korben": 0, "Zataz": 1, "HackerSploit": 0, "NetworkChuck": 0,
    "Bellingcat": 1, "Risky Business": 2, "Troy Hunt": 2,
    "Schneier on Security": 1, "DoublePulsar": 2, "Pen Test Partners": 1,
}


@dataclass
class Article:
    source: str
    title: str
    link: str
    date: datetime
    category: str = ALERTS
    detail: str = ""
    tags: str = ""
    score: int = 0
    severity: str = ""
    countries: tuple[str, ...] = ()                    # pays de l'empreinte IBM cités
    stack: tuple[str, ...] = ()                        # produits de ta stack cités (Box, Slack…)
    cves: tuple = ()                                   # CVE distinctes citées (titre + résumé)
    ttps: tuple[str, ...] = ()                         # techniques MITRE ATT&CK détectées
    actors: tuple[str, ...] = ()                       # acteurs canoniques détectés
    epss: float | None = None                          # probabilité d'exploitation (0 à 1)
    cvss: float | None = None                          # gravité technique (0 à 10)
    also_covered: list[tuple[str, str]] = field(default_factory=list)  # (source, lien) de la même CVE


# --- Mémoire des articles déjà envoyés --------------------------------------
def load_seen_links() -> list[str]:
    """Liste ORDONNÉE (du plus ancien au plus récent) : permet de tronquer proprement."""
    try:
        data = json.loads(Path(SEEN_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        log.warning("seen.json unreadable (%s): starting from scratch", exc)
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _write_json_atomic(path: str | Path, data) -> bool:
    """Écrit un JSON via un fichier temporaire puis os.replace (atomique)."""
    tmp = Path(f"{path}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return True
    except OSError as exc:
        log.warning("Cannot write %s: %s", path, exc)
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def save_seen_links(previous: list[str], new_links: list[str]) -> None:
    known = set(previous)
    merged = previous + [link for link in new_links if link not in known]
    _write_json_atomic(SEEN_FILE, merged[-SEEN_MAX:])


# --- Statistiques historiques (SQLite) --------------------------------------
# Les noms de colonnes restent en français : les bases déjà commitées dans le dépôt
# doivent rester lisibles sans migration.
def open_db() -> sqlite3.Connection | None:
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS articles (
                lien TEXT PRIMARY KEY, vu_le TEXT NOT NULL, source TEXT, categorie TEXT,
                titre TEXT, score INTEGER, criticite TEXT, nb_cves INTEGER, ransomware INTEGER
            );
            CREATE TABLE IF NOT EXISTS cves (
                cve TEXT PRIMARY KEY, vue_le TEXT NOT NULL, epss REAL, cvss REAL, kev INTEGER DEFAULT 0,
                ransomware INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_articles_date ON articles(vu_le);
            CREATE INDEX IF NOT EXISTS idx_cves_date ON cves(vue_le);
            CREATE TABLE IF NOT EXISTS meta (
                cle TEXT PRIMARY KEY, valeur TEXT NOT NULL
            );
            """
        )
        # Migration : les bases créées par les anciennes versions n'ont pas la colonne « ransomware »
        columns = {row[1] for row in conn.execute("PRAGMA table_info(cves)")}
        if "ransomware" not in columns:
            conn.execute("ALTER TABLE cves ADD COLUMN ransomware INTEGER DEFAULT 0")
            conn.commit()
        return conn
    except sqlite3.Error as exc:
        log.warning("Stats database unavailable (%s): report sent without history", exc)
        return None


def meta_get(conn: sqlite3.Connection | None, cle: str) -> str | None:
    """Table clé/valeur minuscule : retient la date du dernier rapport envoyé."""
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT valeur FROM meta WHERE cle = ?", (cle,)).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def meta_set(conn: sqlite3.Connection | None, cle: str, valeur: str) -> None:
    if conn is None:
        return
    try:
        conn.execute(
            "INSERT INTO meta (cle, valeur) VALUES (?, ?) "
            "ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur", (cle, valeur))
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("Could not store %s: %s", cle, exc)


def load_cvss_cache(conn: sqlite3.Connection | None) -> dict[str, float]:
    """CVSS déjà connus : évite de ré-interroger le NVD (limité en débit)."""
    if conn is None:
        return {}
    try:
        return {c: float(s) for c, s in conn.execute("SELECT cve, cvss FROM cves WHERE cvss IS NOT NULL")}
    except sqlite3.Error:
        return {}


def store_stats(conn: sqlite3.Connection | None, groups: dict[str, list[Article]],
                infos: dict[str, dict], today: str) -> None:
    if conn is None:
        return
    try:
        articles = [a for v in groups.values() for a in v]
        conn.executemany(
            "INSERT OR IGNORE INTO articles "
            "(lien, vu_le, source, categorie, titre, score, criticite, nb_cves, ransomware) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [(a.link, today, a.source, a.category, a.title, a.score, a.severity,
              len(a.cves), int("🔥" in a.tags)) for a in articles],
        )
        # La CVE d'une entrée KEV est celle de son titre (la description peut en citer d'autres)
        kev = {c for a in articles if a.source == SOURCE_KEV for c in extract_cves(a.title)}
        ransom = {c for a in articles if a.source == SOURCE_KEV and "🔥" in a.tags
                  for c in extract_cves(a.title)}
        conn.executemany(
            "INSERT INTO cves (cve, vue_le, epss, cvss, kev, ransomware) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(cve) DO UPDATE SET "
            "epss=COALESCE(excluded.epss, cves.epss), cvss=COALESCE(excluded.cvss, cves.cvss), "
            "kev=MAX(COALESCE(cves.kev, 0), excluded.kev), "
            "ransomware=MAX(COALESCE(cves.ransomware, 0), excluded.ransomware)",
            [(c, today, i.get("epss"), i.get("cvss"), int(c in kev), int(c in ransom))
             for c, i in infos.items()],
        )
        cutoff = (datetime.fromisoformat(today) - timedelta(days=DB_RETENTION_DAYS)).date().isoformat()
        conn.execute("DELETE FROM articles WHERE vu_le < ?", (cutoff,))
        # On garde les CVE KEV : elles servent aux rappels et au classement des fournisseurs.
        conn.execute("DELETE FROM cves WHERE vue_le < ? AND COALESCE(kev, 0) = 0", (cutoff,))
        conn.commit()
    except (sqlite3.Error, ValueError) as exc:
        log.warning("Could not store statistics: %s", exc)


def sync_kev(conn: sqlite3.Connection | None, vulns: list[dict]) -> None:
    """Aligne la base sur le catalogue KEV complet.

    Une CVE vue d'abord dans un article puis entrée au KEV est marquée kev=1 (et ransomware=1 si le
    CISA le signale), même si l'entrée KEV elle-même n'a pas été affichée."""
    if conn is None or not vulns:
        return
    try:
        conn.executemany(
            "UPDATE cves SET kev=1, ransomware=MAX(COALESCE(ransomware, 0), ?) WHERE cve=?",
            [(int(v.get("knownRansomwareCampaignUse") == "Known"), str(v["cveID"]).upper())
             for v in vulns if isinstance(v, dict) and v.get("cveID")],
        )
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("KEV synchronization failed: %s", exc)


def kev_reminders(conn: sqlite3.Connection | None, session: requests.Session, today: str,
                  already_shown: set[str], n: int = REMINDERS_N, max_days: int = REMINDERS_DAYS,
                  epss_min: float = REMINDERS_EPSS_MIN) -> list[dict]:
    """CVE du KEV vues pour la 1re fois il y a 1 à `max_days` jours et toujours dangereuses.

    « Dangereuse » = EPSS du jour >= epss_min, ou utilisée par des ransomwares. L'EPSS est
    re-téléchargé (il évolue chaque jour). `days` = ancienneté de la 1re mention dans CE rapport."""
    if conn is None:
        return []
    try:
        now = datetime.fromisoformat(today).date()
        start = (now - timedelta(days=max_days)).isoformat()
        rows = conn.execute(
            "SELECT cve, vue_le, COALESCE(ransomware, 0) FROM cves "
            "WHERE kev=1 AND vue_le < ? AND vue_le >= ?", (today, start)).fetchall()
    except (sqlite3.Error, ValueError) as exc:
        log.warning("Reminders unavailable: %s", exc)
        return []
    rows = [row for row in rows if row[0] not in already_shown]
    if not rows:
        return []
    epss = fetch_epss(session, [cve for cve, _, _ in rows])
    reminders = []
    for cve, seen_on, ransom in rows:
        probability = epss.get(cve)
        if not ransom and (probability is None or probability < epss_min):
            continue
        reminders.append({
            "cve": cve,
            "days": (now - datetime.fromisoformat(seen_on).date()).days,
            "epss": probability,
            "ransomware": bool(ransom),
        })
    reminders.sort(key=lambda r: (r["ransomware"], r["epss"] or 0.0), reverse=True)
    return reminders[:n]


def weekly_stats(conn: sqlite3.Connection | None, today: str) -> dict | None:
    """Les 7 jours précédant ce rapport, comparés aux 7 jours d'avant (le jour courant est exclu)."""
    if conn is None:
        return None
    try:
        now = datetime.fromisoformat(today).date()
        d7 = (now - timedelta(days=7)).isoformat()
        d14 = (now - timedelta(days=14)).isoformat()

        def window(start: str, end: str) -> dict:
            total, crit, imp = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(criticite='🔴'),0), COALESCE(SUM(criticite='🟠'),0) "
                "FROM articles WHERE vu_le >= ? AND vu_le < ?", (start, end)).fetchone()
            cves = conn.execute(
                "SELECT COUNT(*) FROM cves WHERE vue_le >= ? AND vue_le < ?", (start, end)).fetchone()[0]
            return {"articles": total, "critical": crit, "important": imp, "cves": cves}

        days = conn.execute(
            "SELECT COUNT(DISTINCT vu_le) FROM articles WHERE vu_le >= ? AND vu_le < ?",
            (d7, today)).fetchone()[0]
        if days < 2:  # pas assez d'historique pour une tendance
            return None
        top = conn.execute(
            "SELECT source, COUNT(*) AS n FROM articles WHERE vu_le >= ? AND vu_le < ? "
            "GROUP BY source ORDER BY n DESC, source LIMIT 3", (d7, today)).fetchall()
        return {"current": window(d7, today), "previous": window(d14, d7), "top": top,
                "active_days": days}
    except (sqlite3.Error, ValueError) as exc:
        log.warning("Statistics unavailable: %s", exc)
        return None


def trend_line(stats: dict) -> str:
    current, previous = stats["current"], stats["previous"]
    evolution = ""
    if previous["articles"] > 0:
        delta = (current["articles"] - previous["articles"]) / previous["articles"] * 100
        evolution = f" ({delta:+.0f} % vs previous week)"
    top = ", ".join(f"{s} ({n})" for s, n in stats["top"])
    return (f"{current['articles']} items{evolution} · 🔴 {current['critical']} · "
            f"🟠 {current['important']} · {current['cves']} new CVE · "
            f"most active sources: {top}")


# --- Collecte ----------------------------------------------------------------
def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        # Un serveur peut renvoyer Retry-After: 3600 : ne pas bloquer le run une heure.
        respect_retry_after_header=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    # Certains pare-feux refusent un client qui n'annonce pas de langue ; c'est sans risque ici.
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9,fr;q=0.6"})
    return session


_local = threading.local()


def thread_session() -> requests.Session:
    """Une session par thread : requests ne garantit pas le partage d'une Session."""
    session = getattr(_local, "session", None)
    if session is None:
        session = _local.session = create_session()
    return session


def analyse_badges(text: str, countries: tuple[str, ...] = ()) -> str:
    """Drapeaux des pays cités, puis les marqueurs de nature (cible, campagne, menace, acteur)."""
    badges = [COUNTRIES[code]["flag"] for code in countries[:MAX_COUNTRY_FLAGS] if code in COUNTRIES]
    if detect_stack(text):
        badges.append("🧰")
    if RE_TARGETS.search(text):
        badges.append("🎯")
    if _positive(RE_CAMPAIGN, text):
        badges.append("⚡")
    if _positive(RE_THREATS, text):
        badges.append("💥")
    if RE_ACTORS.search(text):
        badges.append("🕵️")
    return " ".join(badges)


def collect_rss(session: requests.Session, source: dict, since: datetime,
                seen: set[str]) -> tuple[list[Article], str | None]:
    """Retourne (articles, erreur_ou_None)."""
    try:
        # Accept propre aux flux : un lecteur RSS annonce les types qu'il sait lire. Cet en-tête
        # reste local a cet appel pour ne pas modifier les reponses JSON (NVD, KEV, GitHub).
        response = session.get(source["url"], timeout=TIMEOUT, headers={"Accept": _FEED_ACCEPT})
        response.raise_for_status()
    except requests.RequestException as exc:
        log.warning("%s: %s", source["name"], exc)
        return [], f"{source['name']}: {exc}"

    try:
        feed = feedparser.parse(response.content)
    except Exception as exc:  # noqa: BLE001 - un flux exotique ne doit pas tuer la source
        log.warning("%s: unreadable feed (%s)", source["name"], exc)
        return [], f"{source['name']}: unreadable feed ({type(exc).__name__})"

    if feed.bozo and not feed.entries:
        # Sans ce message, une reponse anti-bot (200 mais pas du XML) faisait disparaitre la
        # source du journal sans laisser aucune trace : panne invisible.
        log.warning("%s: unreadable feed (no entries, bozo=%s)",
                    source["name"], feed.get("bozo_exception"))
        return [], f"{source['name']}: unreadable feed"

    articles = []
    filtered = source.get("filter", False)
    skipped = 0
    for entry in feed.entries:
        t = (entry.get("published_parsed") or entry.get("updated_parsed")
             or entry.get("created_parsed"))
        if not t:
            continue
        try:
            date = datetime(*t[:6], tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        if date < since:
            continue
        # Un article sans lien n'a pas de page à ouvrir : ne pas utiliser l'URL du flux.
        raw_link = (entry.get("link") or "").strip()
        if not raw_link:
            continue
        link = urljoin(source["url"], raw_link)
        if not link.startswith(("http://", "https://")):
            continue  # refuse javascript:, data:, etc. : le lien finit dans un href du mail
        if not IGNORE_SEEN and link in seen:
            continue
        title = (entry.get("title") or "Untitled item").strip()[:300]
        if source.get("translate"):
            title = translate_german(title)
        text = _entry_text(entry)
        if filtered and not is_relevant(text):
            skipped += 1
            log.info("  skipped (off-topic) [%s]: %s", source["name"], title)
            continue
        short = _short_text(entry)
        countries = detect_countries(short)
        # Une source nationale est rattachée à son pays même si le texte ne le nomme pas.
        home = source.get("country")
        if home and home not in countries:
            countries = (home,) + countries
        score, _ = compute_criticality(short)
        score += SOURCE_WEIGHTS.get(source["name"], 0)
        articles.append(
            Article(
                source=source["name"],
                title=title,
                link=link,
                date=date,
                category=source["category"],
                tags=analyse_badges(short, countries),
                score=score,
                severity=severity_badge(score),
                countries=countries,
                stack=detect_stack(short),
                cves=tuple(sorted(extract_cves(short))),
                ttps=detect_ttps(short),
                actors=detect_actors(short),
            )
        )
    # Les plus dangereux d'abord : si le plafond par source est atteint, on garde l'essentiel
    articles.sort(key=lambda a: (a.score, a.date), reverse=True)
    log.info("%s: %d new%s", source["name"], len(articles),
             f", {skipped} off-topic skipped" if skipped else "")
    return articles[: source.get("max", MAX_PER_SOURCE)], None


def collect_source(source: dict, since: datetime, seen: set[str]) -> tuple[list[Article], str | None]:
    """Frontière de fiabilité : aucune exception inattendue ne sort d'une source."""
    try:
        return collect_rss(thread_session(), source, since, seen)
    except Exception as exc:  # noqa: BLE001
        log.exception("Source %s: unexpected failure", source["name"])
        return [], f"{source['name']}: unexpected error ({type(exc).__name__})"


def check_feeds(session: requests.Session | None = None) -> int:
    """Mode `--check-feeds` : teste les flux et signale les morts, sans envoyer d'e-mail."""
    session = session or create_session()
    ok = 0
    problems: list[str] = []
    for source in RSS_SOURCES:
        try:
            response = session.get(source["url"], timeout=TIMEOUT, headers={"Accept": _FEED_ACCEPT})
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            if not feed.entries:
                problems.append(source["name"])
                print(f"KO   {source['name']:<32} 0 entry")
                continue
            latest = ""
            for entry in feed.entries:
                t = entry.get("published_parsed") or entry.get("updated_parsed")
                if t:
                    try:
                        latest = datetime(*t[:6], tzinfo=timezone.utc).strftime("%Y-%m-%d")
                    except (TypeError, ValueError):
                        pass
                    break
            ok += 1
            print(f"OK   {source['name']:<32} {len(feed.entries):3d} entries  latest={latest or '?'}")
        except (requests.RequestException, OSError) as exc:
            problems.append(source["name"])
            print(f"KO   {source['name']:<32} {exc}")
    print(f"\n{ok}/{len(RSS_SOURCES)} feeds OK; problems: {', '.join(problems) or 'none'}")
    return 0 if not problems else 1


def check_country_links(session: requests.Session | None = None) -> int:
    """Mode `--check-links` : vérifie que tous les liens nationaux des rubriques répondent."""
    session = session or create_session()
    ok = 0
    problems: list[str] = []
    for code, info in COUNTRIES.items():
        for label, url in info["links"]:
            try:
                response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
                status = response.status_code
            except requests.RequestException as exc:
                problems.append(f"{code} {label}")
                print(f"KO   {info['flag']} {label:<24} {exc}")
                continue
            if status >= 400:
                problems.append(f"{code} {label} ({status})")
                print(f"KO   {info['flag']} {label:<24} HTTP {status}")
            else:
                ok += 1
                print(f"OK   {info['flag']} {label:<24} HTTP {status}")
    print(f"\n{ok}/{ok + len(problems)} country links OK; problems: {', '.join(problems) or 'none'}")
    return 0 if not problems else 1


# --- Cache du catalogue KEV ---------------------------------------------------
def _read_kev_cache() -> list[dict]:
    try:
        data = json.loads(Path(KEV_CACHE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities", [])
    return [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []


def _write_kev_cache(vulns: list[dict]) -> None:
    keep = ("cveID", "dateAdded", "vendorProject", "product", "shortDescription",
            "knownRansomwareCampaignUse", "requiredAction", "dueDate", "cwes")
    reduced = [{k: v.get(k) for k in keep} for v in vulns if isinstance(v, dict) and v.get("cveID")]
    _write_json_atomic(
        KEV_CACHE_FILE,
        {"fetched_at": datetime.now(timezone.utc).isoformat(), "vulnerabilities": reduced},
    )


@contextlib.contextmanager
def ipv4_only():
    """Force IPv4 le temps d'un appel.

    L'API Ransomware.live publie un enregistrement AAAA, mais le vhost IPv6 sert le site et
    renvoie 404 sur /v2/... : depuis un reseau qui privilegie IPv6 (Windows, la plupart des
    operateurs), l'API parait hors service alors qu'elle repond parfaitement en IPv4.
    """
    original = socket.getaddrinfo

    def _filtre(*args, **kwargs):
        return [r for r in original(*args, **kwargs) if r[0] == socket.AF_INET]

    socket.getaddrinfo = _filtre
    try:
        yield
    finally:
        socket.getaddrinfo = original


def collect_ransomware_victims(session: requests.Session, since: datetime):
    """Victimes publiees sur les sites de fuite (API v2), avec leur pays en champ structure.

    Complementaire du flux RSS Ransomware.live : celui-ci suit la couverture de presse, pas les
    publications des groupes. Aucun recouvrement constate entre les deux jeux de liens.
    """
    url = "https://api.ransomware.live/v2/recentvictims"
    entetes: dict[str, str] = {}
    # API PRO : cle gratuite, en-tete X-Api-Key, mais hote distinct. Non deployee a ce jour
    # (api-pro renvoie 404 sur /v2/*) : on tente puis on retombe sur l'acces anonyme.
    if RANSOMWARE_API_KEY:
        url = "https://api-pro.ransomware.live/v2/recentvictims"
        entetes = {"X-Api-Key": RANSOMWARE_API_KEY}
    try:
        with ipv4_only():
            response = session.get(url, timeout=TIMEOUT, headers=entetes)
            if response.status_code == 404 and entetes:
                log.warning("%s: PRO endpoint unavailable, falling back to the free API",
                            SOURCE_RANSOMWARE_API)
                url = "https://api.ransomware.live/v2/recentvictims"
                response = session.get(url, timeout=TIMEOUT, headers={})
            response.raise_for_status()
            victimes = response.json()
        if not isinstance(victimes, list):
            raise ValueError("invalid payload")
    except (requests.RequestException, ValueError, AttributeError) as exc:
        log.warning("%s: %s", SOURCE_RANSOMWARE_API, exc)
        return [], f"{SOURCE_RANSOMWARE_API}: {exc}"

    articles = []
    for v in victimes:
        if not isinstance(v, dict):
            continue
        try:
            date = datetime.strptime(str(v.get("attackdate") or "")[:10], "%Y-%m-%d")
            date = date.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        if date < since:
            continue
        victim = str(v.get("victim") or "").strip()
        group = str(v.get("group") or "").strip()
        link = str(v.get("url") or "").strip()
        if not victim or not link.startswith(("http://", "https://")):
            continue
        code = str(v.get("country") or "").strip().upper()
        # Le pays vient du champ structure : la rubrique nationale se remplit sans detection textuelle.
        pays = (code,) if code in COUNTRIES else ()
        # Meme logique que le KEV : la publication d'une victime est une attaque averee, donc un
        # socle de points au-dessus de la detection par mots-cles.
        texte = f"{victim} {group} ransomware attack"
        score, _ = compute_criticality(texte)
        score += 3
        if pays:
            # Benelux et France pesent plus lourd que le reste de l'empreinte.
            score += 3 if code in HOME_COUNTRIES else 1
        detail = " · ".join(x for x in (
            f"Groupe : {group}" if group else "",
            f"Secteur : {v.get('activity')}" if v.get("activity") else "",
            f"Données : {v.get('data_size')}" if v.get("data_size") else "",
        ) if x)
        articles.append(Article(
            source=SOURCE_RANSOMWARE_API,
            title=(f"{victim} — revendiqué par {group}" if group else victim)[:300],
            link=link,
            date=date,
            category=DARKWEB,
            detail=detail,
            tags=analyse_badges(texte, pays),
            score=score,
            severity=severity_badge(score),
            countries=pays,
        ))
    log.info("%s: %d new", SOURCE_RANSOMWARE_API, len(articles))
    return articles, None


def collect_cisa_kev(session: requests.Session, seen: set[str]):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        if not isinstance(vulns, list):
            raise ValueError("invalid vulnerabilities field")
    except (requests.RequestException, ValueError, AttributeError) as exc:
        vulns = _read_kev_cache()
        if not vulns:
            log.warning("CISA KEV: %s", exc)
            return [], f"CISA KEV: {exc}"
        log.warning("CISA KEV unavailable (%s): using local cache (%d entries)",
                    exc, len(vulns))
    else:
        if vulns:  # ne jamais écraser un cache valide avec une réponse vide
            _write_kev_cache(vulns)

    KEV_VULNS[:] = vulns  # catalogue complet : classement des fournisseurs + synchronisation de la base
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEV_DAYS)).date()
    articles = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        try:
            date = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            continue
        if date.date() < cutoff:
            continue
        cve = str(v.get("cveID") or "unknown CVE")
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if not IGNORE_SEEN and link in seen:
            continue
        title = f"{cve}: {v.get('vendorProject', '?')} {v.get('product', '?')}"[:300]
        description = v.get("shortDescription") or ""
        text = f"{title} {description}"
        countries = detect_countries(text)
        tags = analyse_badges(text, countries)
        score, _ = compute_criticality(text)
        score += 5  # toute entrée du KEV est, par définition, exploitée dans la nature
        if v.get("knownRansomwareCampaignUse") == "Known":
            tags = f"🔥 {tags}".strip()
            score += 5
        if KEV_ALWAYS_CRITICAL:
            score = max(score, CRITICAL_THRESHOLD)
        articles.append(
            Article(
                source=SOURCE_KEV,
                title=title,
                link=link,
                date=date,
                category=ALERTS,
                detail=description,
                tags=tags,
                score=score,
                severity=severity_badge(score),
                countries=countries,
                stack=detect_stack(text),
                cves=tuple(sorted(extract_cves(title) | extract_cves(description))),
                ttps=detect_ttps(text),
                actors=detect_actors(text),
            )
        )
    articles.sort(key=lambda a: (a.score, a.date), reverse=True)
    log.info("CISA KEV: %d new", len(articles))
    return articles[:MAX_KEV], None


def collect_github_advisories(session: requests.Session, since: datetime):
    """GitHub Advisory Database (API) : complète les flux RSS pour l'open source."""
    url = "https://api.github.com/advisories"
    try:
        r = session.get(url, params={"per_page": 100, "sort": "published",
                                     "direction": "desc"}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("GitHub Advisory: %s", exc)
        return [], f"GitHub Advisory: {exc}"
    if not isinstance(data, list):
        return [], "GitHub Advisory: unexpected format"

    articles = []
    for adv in data:
        if not isinstance(adv, dict):
            continue
        try:
            date = datetime.fromisoformat(str(adv.get("published_at", "")).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if date < since:
            continue
        link = adv.get("html_url") or ""
        if not link.startswith("https://"):
            continue
        cve = adv.get("cve_id") or ""
        ghsa = adv.get("ghsa_id") or ""
        identifier = cve or ghsa or "GHSA"
        summary = adv.get("summary") or "GitHub advisory"
        title = f"{identifier}: {summary}"[:300]
        cvss = (adv.get("cvss") or {}).get("score")
        severity = (adv.get("severity") or "").lower()
        score = 4
        if severity == "critical":
            score += 5
        elif severity == "high":
            score += 3
        elif severity == "moderate":
            score += 1
        if isinstance(cvss, (int, float)) and cvss >= 9:
            score += 2
        score += SOURCE_WEIGHTS.get(SOURCE_GITHUB, 0)
        cves = extract_cves(summary)
        if cve:
            cves.add(str(cve).upper())
        text = f"{title} {summary}"
        countries = detect_countries(text)
        articles.append(
            Article(
                source=SOURCE_GITHUB,
                title=title,
                link=link,
                date=date,
                category=ALERTS,
                detail=summary[:800],
                tags=analyse_badges(text, countries),
                score=score,
                severity=severity_badge(score),
                countries=countries,
                stack=detect_stack(text),
                cves=tuple(sorted(cves)),
                ttps=detect_ttps(text),
                actors=detect_actors(text),
                cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
            )
        )
    articles.sort(key=lambda a: (a.score, a.date), reverse=True)
    log.info("GitHub Advisory: %d new", len(articles))
    return articles[:MAX_KEV], None


def top_vendors(vulns: list[dict], today: str, days: int = VENDORS_DAYS,
                n: int = VENDORS_N) -> list[dict]:
    """Fournisseurs avec le plus de failles ajoutées au KEV sur `days` jours.

    Compare au classement des `days` précédents : ▲ (monte), ▼ (descend), = (stable), 🆕 (absent avant).
    Attention : ce sont des vulnérabilités EXPLOITÉES (entrées KEV), pas un nombre d'attaques."""
    now = datetime.fromisoformat(today).date()
    end = now.isoformat()
    start = (now - timedelta(days=days)).isoformat()
    start_previous = (now - timedelta(days=2 * days)).isoformat()

    names: dict[str, str] = {}          # clé insensible à la casse -> graphie d'affichage
    current: Counter = Counter()
    previous: Counter = Counter()
    for v in vulns:
        if not isinstance(v, dict):
            continue
        d = str(v.get("dateAdded", ""))
        name = str(v.get("vendorProject", "")).strip() or "?"
        key = name.casefold()
        if start <= d <= end:
            current[key] += 1
        elif start_previous <= d < start:
            previous[key] += 1
        else:
            continue
        names.setdefault(key, name)

    def rank(counter: Counter) -> list[str]:
        return [k for k, _ in sorted(counter.items(), key=lambda kv: (-kv[1], names[kv[0]].casefold()))]

    previous_rank = {k: i for i, k in enumerate(rank(previous), 1)}
    result = []
    for position, key in enumerate(rank(current)[:n], 1):
        if key not in previous_rank:
            arrow = "🆕"
        elif previous_rank[key] > position:
            arrow = "▲"
        elif previous_rank[key] < position:
            arrow = "▼"
        else:
            arrow = "="
        result.append({"vendor": names[key], "count": current[key],
                       "previous": previous.get(key, 0), "arrow": arrow})
    return result


# --- Enrichissement : EPSS (FIRST) et CVSS (NVD) -----------------------------
_EPSS_CACHE: dict[str, float] | None = None


def _load_epss_bulk(session: requests.Session) -> dict[str, float]:
    """Télécharge le CSV quotidien EPSS (une requête, tous les scores)."""
    try:
        r = session.get(EPSS_CSV_URL, timeout=60)
        r.raise_for_status()
        with gzip.open(io.BytesIO(r.content), "rt", encoding="utf-8-sig", newline="") as stream:
            rows = (line for line in stream if not line.startswith("#"))
            result: dict[str, float] = {}
            for row in csv.DictReader(rows):
                try:
                    result[str(row["cve"]).upper()] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
            return result
    except (requests.RequestException, OSError, ValueError, KeyError) as exc:
        log.warning("EPSS (CSV) unavailable: %s", exc)
        return {}


def fetch_epss(session: requests.Session, cves: list[str]) -> dict[str, float]:
    """EPSS = probabilité (0 à 1) qu'une CVE soit exploitée dans les 30 prochains jours.

    Utilise le CSV quotidien (usage recommandé pour du bulk), avec repli sur l'API CVE par CVE.
    """
    global _EPSS_CACHE
    if _EPSS_CACHE is None:
        _EPSS_CACHE = _load_epss_bulk(session)
    if _EPSS_CACHE:
        result = {c: _EPSS_CACHE[c] for c in cves if c in _EPSS_CACHE}
        log.info("EPSS: %d/%d CVE filled (CSV)", len(result), len(cves))
        return result

    result = {}
    for i in range(0, len(cves), 50):
        batch = cves[i:i + 50]
        try:
            r = session.get(f"{EPSS_URL}?cve={','.join(batch)}", timeout=20)
            r.raise_for_status()
            for row in r.json().get("data", []):
                try:
                    result[str(row["cve"]).upper()] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        except (requests.RequestException, ValueError, AttributeError) as exc:
            log.warning("EPSS (API) unavailable: %s", exc)
            break
    log.info("EPSS: %d/%d CVE filled (API)", len(result), len(cves))
    return result


def extract_cvss(cve_json: dict) -> float | None:
    metrics = cve_json.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def fetch_cvss(session: requests.Session, cve: str) -> tuple[float | None, bool]:
    """Retourne (score_ou_None, limite_de_debit_atteinte)."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = session.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=20)
    except requests.RequestException as exc:
        log.warning("NVD %s: %s", cve, exc)
        return None, False
    if r.status_code == 403:
        log.warning("NVD 403 for %s: missing/invalid API key or access denied (%s)",
                    cve, r.text[:160])
        return None, True
    if r.status_code == 429:
        log.warning("NVD: rate limit reached, stopping CVSS lookups for this run")
        return None, True
    if r.status_code != 200:
        return None, False
    try:
        vulns = r.json().get("vulnerabilities", [])
    except ValueError:
        return None, False
    if not vulns:
        return None, False  # CVE trop récente, pas encore analysée par le NVD
    return extract_cvss(vulns[0].get("cve", {})), False


def enrich(session: requests.Session, groups: dict[str, list[Article]],
           cvss_cache: dict[str, float]) -> dict[str, dict]:
    """Ajoute EPSS/CVSS aux articles qui citent des CVE, puis recalcule score et pastille."""
    articles = [a for v in groups.values() for a in v if a.cves]
    if not articles:
        return {}
    all_cves = sorted({c for a in articles for c in a.cves})
    epss = fetch_epss(session, all_cves)

    # CVSS : CVE des articles les plus dangereux d'abord, en respectant la limite de débit du NVD
    order: list[str] = []
    for a in sorted(articles, key=lambda x: x.score, reverse=True):
        for c in a.cves:
            if c not in order:
                order.append(c)
    cvss = {c: cvss_cache[c] for c in all_cves if c in cvss_cache}
    to_fetch = [c for c in order if c not in cvss][:MAX_CVSS]
    pause = 0.7 if NVD_API_KEY else 6.5
    for i, c in enumerate(to_fetch):
        if i:
            time.sleep(pause)
        score, rate_limited = fetch_cvss(session, c)
        if score is not None:
            cvss[c] = score
        if rate_limited:
            break
    log.info("CVSS: %d/%d CVE filled (cache included)", len(cvss), len(all_cves))

    for a in articles:
        e_values = [epss[c] for c in a.cves if c in epss]
        c_values = [cvss[c] for c in a.cves if c in cvss]
        a.epss = max(e_values) if e_values else None
        a.cvss = max(c_values) if c_values else None
        a.score += enrichment_bonus(a.epss, a.cvss)
        if a.source == SOURCE_KEV and KEV_ALWAYS_CRITICAL:
            a.score = max(a.score, CRITICAL_THRESHOLD)
        a.severity = severity_badge(a.score)
    for items in groups.values():
        items.sort(key=lambda a: (a.score, a.date), reverse=True)
    return {c: {"epss": epss.get(c), "cvss": cvss.get(c)} for c in all_cves}


# --- Rendu -------------------------------------------------------------------
def compute_totals(groups: dict[str, list[Article]]) -> dict:
    articles = [a for v in groups.values() for a in v]
    cves = {c for a in articles for c in a.cves}
    ttp_top = Counter(c for a in articles for c in a.ttps).most_common(5)
    actor_top = Counter(c for a in articles for c in a.actors).most_common(5)
    by_country = Counter(c for a in articles for c in a.countries)
    return {
        "total": len(articles),
        "critical": sum(1 for a in articles if a.severity == "🔴"),
        "important": sum(1 for a in articles if a.severity == "🟠"),
        "cves": len(cves),
        "cves_ransomware": len({c for a in articles if "🔥" in a.tags for c in a.cves}),
        "attacks": sum(1 for a in articles if a.source == SOURCE_RANSOMWARE_LIVE),
        "campaigns": sum(1 for a in articles if "⚡" in a.tags),
        "active_sources": len(groups),
        "total_sources": len(RSS_SOURCES) + EXTRA_SOURCES,
        "by_country": by_country,
        "countries": len(by_country),
        "ttp_top": ttp_top,
        "actor_top": actor_top,
    }


def top_priorities(groups: dict[str, list[Article]], n: int = TOP_N,
                   max_kev: int = TOP_MAX_KEV) -> list[Article]:
    """Importants/critiques uniquement, triés par score ; les entrées KEV sont plafonnées."""
    every = [a for v in groups.values() for a in v if a.score >= IMPORTANT_THRESHOLD]
    every.sort(key=lambda a: (a.score, a.date), reverse=True)
    chosen: list[Article] = []
    kev_count = 0
    for a in every:
        if a.source == SOURCE_KEV:
            if kev_count >= max_kev:
                continue
            kev_count += 1
        chosen.append(a)
        if len(chosen) >= n:
            break
    return chosen


def limit_for_email(groups: dict[str, list[Article]],
                    max_total: int | None = None) -> dict[str, list[Article]]:
    """Réduit le nombre d'articles affichés pour rester sous la limite de Gmail.

    Distribution circulaire (rang 0 de chaque source, puis rang 1...) : on garde
    les meilleurs scores de chaque source plutôt que de vider les dernières catégories.
    """
    if max_total is None:
        max_total = MAX_EMAIL_ARTICLES
    total = sum(len(v) for v in groups.values())
    if total <= max_total:
        # On filtre aussi ici : un groupe vide ferait planter le rendu (articles[0]).
        return {source: articles for source, articles in groups.items() if articles}
    result: dict[str, list[Article]] = {source: [] for source in groups}
    position = 0
    remaining = max_total
    while remaining > 0:
        added = False
        for source, articles in groups.items():
            if position < len(articles) and remaining > 0:
                result[source].append(articles[position])
                remaining -= 1
                added = True
        if not added:
            break
        position += 1
    log.info("E-mail: %d/%d items displayed (cap %d)", max_total - remaining, total, max_total)
    return {source: articles for source, articles in result.items() if articles}


def country_sections(groups: dict[str, list[Article]],
                     per_country: int = MAX_ARTICLES_PER_COUNTRY,
                     max_total: int = MAX_COUNTRY_ARTICLES) -> list[tuple[str, list[Article]]]:
    """Articles rattachés à chaque pays de l'empreinte IBM, le plus fourni d'abord.

    Un article peut apparaître dans plusieurs pays : la liste par pays ne garde que le titre,
    le détail complet restant dans les rubriques par source.
    """
    ranked = sorted((a for v in groups.values() for a in v),
                    key=lambda a: (a.score, a.date), reverse=True)
    buckets: dict[str, list[Article]] = {}
    budget = max_total
    for a in ranked:
        if budget <= 0:
            break
        for code in a.countries:
            if code not in COUNTRIES:
                continue
            bucket = buckets.setdefault(code, [])
            if len(bucket) < per_country:
                bucket.append(a)
                budget -= 1
    return sorted(buckets.items(), key=lambda kv: (-len(kv[1]), COUNTRIES[kv[0]]["name"]))


def _stack_watch_item(a: Article) -> bool:
    """La rubrique stack ne garde que les articles porteurs d'un signal sécurité.

    Sans ce filtre, « Microsoft 365 » ramènerait toutes les annonces produit ; un article y entre
    donc seulement s'il cite une CVE, une technique/campagne/ransomware, ou si son titre parle
    vraiment de sécurité.
    """
    return bool(a.cves) or any(m in a.tags for m in ("💥", "⚡", "🔥")) or is_relevant(a.title)


def stack_sections(groups: dict[str, list[Article]],
                   per_product: int = MAX_STACK_PER_PRODUCT,
                   max_total: int = MAX_STACK_ARTICLES) -> list[tuple[str, list[Article]]]:
    """Articles rattachés à chaque produit de ta stack, dans l'ordre Box, Slack, Teams, Outlook."""
    ranked = sorted((a for v in groups.values() for a in v),
                    key=lambda a: (a.score, a.date), reverse=True)
    buckets: dict[str, list[Article]] = {}
    budget = max_total
    for a in ranked:
        if budget <= 0:
            break
        if not _stack_watch_item(a):
            continue
        for name in a.stack:
            bucket = buckets.setdefault(name, [])
            if len(bucket) < per_product:
                bucket.append(a)
                budget -= 1
    order = list(STACK_PRODUCTS)
    return sorted(buckets.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)


def _format_epss(epss: float | None) -> str:
    if epss is None:
        return "EPSS n/a"
    return "EPSS <1 %" if epss < 0.01 else f"EPSS {epss * 100:.0f} %"


def _reminder_line(r: dict) -> str:
    parts = [f"seen for {r['days']} d", _format_epss(r["epss"]), "still in KEV"]
    if r["ransomware"]:
        parts.append("🔥 ransomware")
    return " · ".join(parts)


def _vendor_line(f: dict) -> str:
    return f"{f['vendor']} ({f['count']}) {f['arrow']}"


def _badges(a: Article) -> str:
    return " ".join(x for x in (a.severity, a.tags) if x)


def _metrics(a: Article) -> str:
    parts = []
    if a.epss is not None:
        parts.append("EPSS <1 %" if a.epss < 0.01 else f"EPSS {a.epss * 100:.0f} %")
    if a.cvss is not None:
        parts.append(f"CVSS {a.cvss:.1f}")
    return " · ".join(parts)


def _qualifiers(a: Article) -> str:
    parts = []
    if a.ttps:
        parts.append("TTP " + ", ".join(a.ttps))
    if a.actors:
        parts.append("Actor " + ", ".join(a.actors))
    return " · ".join(parts)


def _country_links_html(info: dict) -> str:
    return " · ".join(
        f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">'
        f"{html.escape(label)}</a>"
        for label, url in info["links"]
    )


def _country_links_text(info: dict) -> str:
    return " · ".join(f"{label} ({url})" for label, url in info["links"])


def _cve_links_html(cve: str) -> str:
    c = html.escape(cve, quote=True)
    num = html.escape(cve.replace("CVE-", ""), quote=True)
    return (
        f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" rel="noopener noreferrer">NVD</a> · '
        f'<a href="https://www.exploit-db.com/search?cve={num}" target="_blank" rel="noopener noreferrer">Exploit-DB</a> · '
        f'<a href="https://github.com/advisories?query={c}" target="_blank" rel="noopener noreferrer">GitHub</a>'
    )


def _cve_links_text(cve: str) -> str:
    num = cve.replace("CVE-", "")
    return (
        f"NVD: https://nvd.nist.gov/vuln/detail/{cve} · "
        f"Exploit-DB: https://www.exploit-db.com/search?cve={num} · "
        f"GitHub: https://github.com/advisories?query={cve}"
    )


def render_html(groups: dict[str, list[Article]], errors: list[str],
                stats: dict | None = None,
                reminders: list[dict] | None = None, vendors: list[dict] | None = None,
                *, max_articles: int | None = None) -> str:
    e = html.escape
    c = compute_totals(groups)
    displayed = limit_for_email(groups, max_articles)
    shown = sum(len(v) for v in displayed.values())
    parts = [
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Cyber security watch</title></head>'
        '<body style="font-family:Arial,sans-serif;color:#333;line-height:1.5;max-width:900px;margin:auto">',
        '<h1 style="color:#d9534f;border-bottom:2px solid #d9534f">🛡️ Cyber security &amp; OSINT watch</h1>',
        '<div style="background:#f8f9fa;padding:10px;border-radius:5px;border:1px solid #ddd">'
        f"<b>📊 Dashboard</b><br>{c['total']} item(s) · {WINDOW_HOURS} h window · "
        f"{c['active_sources']}/{c['total_sources']} sources active · {c['cves']} distinct CVE(s)<br>"
        f"🔴 Critical: {c['critical']} · 🟠 Important: {c['important']}<br>"
        f"🔥 CVE exploited by ransomware: {c['cves_ransomware']} · "
        f"🏴‍☠️ Cyberattacks recorded (Ransomware.live): {c['attacks']} · "
        f"⚡ Items reporting a campaign: {c['campaigns']} · "
        f"🌍 IBM countries flagged: {c['countries']}/{len(COUNTRIES)}</div>",
        '<p style="font-size:12px;color:#555">Legend: 🔴 critical · 🟠 important · '
        "🇪🇺🇧🇪🇩🇪… country of the IBM footprint · "
        "🎯 products and stack · 💥 exploitation technique · 🕵️ APT/ransomware actor · "
        "🔥 CVE used by ransomware · ⚡ active campaign · "
        "TTP = MITRE ATT&amp;CK technique · "
        "EPSS = exploitation probability (FIRST) · CVSS = technical severity (NVD)</p>",
    ]
    if c["ttp_top"] or c["actor_top"]:
        details = []
        if c["ttp_top"]:
            details.append("TTP: " + ", ".join(f"{tid} ({n})" for tid, n in c["ttp_top"]))
        if c["actor_top"]:
            details.append("Actors: " + ", ".join(f"{name} ({n})" for name, n in c["actor_top"]))
        parts.append('<p style="font-size:12px;color:#555">' + e(" · ".join(details)) + "</p>")
    if shown < c["total"]:
        parts.append(
            '<p style="background:#eef4ff;padding:8px;border-radius:4px;font-size:12px">'
            f"✂️ {c['total']} items collected, {shown} displayed: "
            "the lowest-priority entries are hidden to avoid e-mail truncation."
            "</p>"
        )
    if errors:
        parts.append(
            '<p style="background:#fff3cd;padding:8px;border-radius:4px">⚠️ Sources in error: '
            + e(" ; ".join(errors))
            + "</p>"
        )

    parts.append('<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:24px">🚨 Top priorities today</h2>')
    top = top_priorities(groups)
    if top:
        parts.append("<ul>")
        for a in top:
            m = _metrics(a)
            metr = f' <small style="color:#666">[{e(m)}]</small>' if m else ""
            qual = _qualifiers(a)
            qual_html = f'<br><small>{e(qual)}</small>' if qual else ""
            cve_html = f'<br><small>{_cve_links_html(a.cves[0])}</small>' if a.cves else ""
            parts.append(
                f'<li style="margin-bottom:6px"><b>{e(_badges(a))}</b> '
                f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(a.title)}</a>{metr} '
                f'<small>({e(a.source)})</small>{qual_html}{cve_html}</li>'
            )
        parts.append("</ul>")
    else:
        parts.append("<p>✅ Nothing critical or important today.</p>")

    if reminders:
        parts.append(
            '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:24px">'
            "🔁 Still relevant</h2><ul>"
        )
        for r in reminders:
            cve = e(r["cve"])
            parts.append(
                f'<li style="margin-bottom:6px"><b>{cve}</b> · {e(_reminder_line(r))}'
                f'<br><small>{_cve_links_html(r["cve"])}</small></li>'
            )
        parts.append("</ul>")

    last_category = None
    for source, articles in displayed.items():
        if articles[0].category != last_category:
            last_category = articles[0].category
            parts.append(
                '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
                f"{e(last_category)}</h2>"
            )
        total_source = len(groups[source])
        label = (f"{source} ({len(articles)}/{total_source})"
                 if len(articles) < total_source else f"{source} ({len(articles)})")
        href = SOURCE_LINKS.get(source)
        if href:
            parts.append(
                '<h3 style="color:#0275d8;margin-bottom:4px">'
                f'<a href="{e(href, quote=True)}" style="color:#0275d8;text-decoration:none" '
                f'target="_blank" rel="noopener noreferrer">{e(label)}</a></h3><ul>'
            )
        else:
            parts.append(f'<h3 style="color:#0275d8">{e(label)}</h3><ul>')
        for a in articles:
            badges = _badges(a)
            tag = f"<b>{e(badges)}</b> " if badges else ""
            m = _metrics(a)
            metr = f' <small style="color:#666">[{e(m)}]</small>' if m else ""
            detail = f"<br><small>{e(a.detail)}</small>" if a.detail else ""
            qual = _qualifiers(a)
            qual_html = f"<br><small>{e(qual)}</small>" if qual else ""
            also = ("<br><small>Also covered by: " + ", ".join(
                f'<a href="{e(link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(src)}</a>'
                for src, link in a.also_covered) + "</small>") if a.also_covered else ""
            parts.append(
                f'<li style="margin-bottom:10px">{tag}'
                f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(a.title)}</a>{metr}{detail}{qual_html}{also}</li>'
            )
        parts.append("</ul>")

    stack_blocks = stack_sections(groups)
    parts.append(
        '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
        f"🧰 Your stack ({e(' · '.join(STACK_PRODUCTS))})</h2>"
    )
    if stack_blocks:
        for name, items in stack_blocks:
            parts.append(f'<h3 style="color:#0275d8">{e(name)} ({len(items)})</h3><ul>')
            for a in items:
                parts.append(
                    f'<li style="margin-bottom:4px">{e(_badges(a))} '
                    f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">'
                    f"{e(a.title)}</a> <small>({e(a.source)})</small></li>"
                )
            parts.append("</ul>")
    else:
        parts.append(
            '<p style="font-size:12px;color:#777">No security item about your stack in this '
            "window.</p>"
        )

    blocks = country_sections(groups)
    parts.append(
        '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
        "🌍 European focus (IBM footprint)</h2>"
    )
    if blocks:
        total_country_items = sum(len(v) for _, v in blocks)
        parts.append(
            '<p style="font-size:11px;color:#888">'
            f"{total_country_items} item(s) across {len(blocks)} of {len(COUNTRIES)} countries where IBM "
            "operates an entity or an office. Titles only: the full entry is listed in the sections above.</p>"
        )
        for code, items in blocks:
            info = COUNTRIES[code]
            parts.append(
                f'<h3 style="color:#0275d8">{info["flag"]} {e(info["name"])} ({len(items)})</h3><ul>'
            )
            for a in items:
                parts.append(
                    f'<li style="margin-bottom:4px">{e(_badges(a))} '
                    f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">'
                    f"{e(a.title)}</a> <small>({e(a.source)})</small></li>"
                )
            parts.append("</ul>")
    else:
        parts.append(
            '<p style="font-size:12px;color:#777">No item mentioned an IBM country in this window.</p>'
        )
    if SHOW_COUNTRY_LINKS:
        parts.append(
            '<p style="font-size:12px;color:#555;margin:18px 0 4px">'
            "<b>🏛️ National CERT &amp; trusted sources</b></p>"
            '<ul style="font-size:12px;line-height:1.6">'
        )
        for code, info in COUNTRIES.items():
            parts.append(
                f'<li>{info["flag"]} {e(info["name"])} — {_country_links_html(info)}</li>'
            )
        parts.append("</ul>")

    if vendors:
        items = " · ".join(e(_vendor_line(f)) for f in vendors)
        parts.append(
            '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">'
            f"🏢 Exploited by vendor ({VENDORS_DAYS} d, KEV — not attack counts)</h2>"
            f'<p style="font-size:13px">{items}</p>'
        )
    if stats:
        parts.append(
            '<h2 style="color:#222;border-bottom:1px solid #ccc;margin-top:28px">📈 Trend</h2>'
            f'<p style="font-size:13px">Previous 7 days: {e(trend_line(stats))}</p>'
        )
    parts.append(
        '<div style="margin-top:26px;padding:12px;background:#f8f9fa;'
        'border-top:3px solid #d9534f;text-align:center">'
        '<p style="margin:0;font-size:15px;color:#333">Generated automatically by Nours_sec_bot</p></div></body></html>'
        )
    return "\n".join(parts)


def render_text(groups: dict[str, list[Article]], errors: list[str],
                stats: dict | None = None,
                reminders: list[dict] | None = None, vendors: list[dict] | None = None,
                *, max_articles: int | None = None) -> str:
    c = compute_totals(groups)
    displayed = limit_for_email(groups, max_articles)
    shown = sum(len(v) for v in displayed.values())
    lines = [
        f"{c['total']} item(s) over {WINDOW_HOURS} h · "
        f"{c['active_sources']}/{c['total_sources']} sources active · "
        f"{c['cves']} CVE · critical: {c['critical']} · "
        f"important: {c['important']} · CVE ransomware: {c['cves_ransomware']} · "
        f"cyberattacks recorded: {c['attacks']} · "
        f"IBM countries flagged: {c['countries']}/{len(COUNTRIES)}"
    ]
    if c["ttp_top"] or c["actor_top"]:
        details = []
        if c["ttp_top"]:
            details.append("TTP: " + ", ".join(f"{tid} ({n})" for tid, n in c["ttp_top"]))
        if c["actor_top"]:
            details.append("Actors: " + ", ".join(f"{name} ({n})" for name, n in c["actor_top"]))
        lines.append(" · ".join(details))
    if shown < c["total"]:
        lines.append(f"({c['total']} items collected, {shown} displayed: "
                     "the lowest-priority ones are hidden to avoid truncation.)")
    if errors:
        lines.append("Sources in error: " + " ; ".join(errors))
    top = top_priorities(groups)
    if top:
        lines.append("\n##### TOP PRIORITIES TODAY #####")
        for a in top:
            m = _metrics(a)
            qual = _qualifiers(a)
            extra = f" [{qual}]" if qual else ""
            cve_extra = f"\n  {_cve_links_text(a.cves[0])}" if a.cves else ""
            lines.append(
                f"- {_badges(a)} {a.title}{f' [{m}]' if m else ''}{extra}\n  {a.link}{cve_extra}"
            )
    if reminders:
        lines.append("\n##### STILL RELEVANT #####")
        for r in reminders:
            lines.append(f"- {r['cve']} · {_reminder_line(r)}\n  {_cve_links_text(r['cve'])}")
    last_category = None
    for source, articles in displayed.items():
        if articles[0].category != last_category:
            last_category = articles[0].category
            lines.append(f"\n##### {last_category.upper()} #####")
        total_source = len(groups[source])
        label = (f"{source} ({len(articles)}/{total_source})"
                 if len(articles) < total_source else f"{source} ({len(articles)})")
        lines.append(f"\n== {label} ==")
        for a in articles:
            badges, m = _badges(a), _metrics(a)
            qual = _qualifiers(a)
            lines.append(
                f"- {badges + ' ' if badges else ''}{a.title}{f' [{m}]' if m else ''}"
                f"{f' [{qual}]' if qual else ''}\n  {a.link}"
                + (f"\n  Also covered by: {', '.join(f'{src} ({link})' for src, link in a.also_covered)}"
                   if a.also_covered else "")
            )

    stack_blocks = stack_sections(groups)
    lines.append("\n##### YOUR STACK (" + " · ".join(STACK_PRODUCTS).upper() + ") #####")
    if stack_blocks:
        for name, items in stack_blocks:
            lines.append(f"\n-- {name} ({len(items)}) --")
            for a in items:
                lines.append(f"- {_badges(a)} {a.title} ({a.source})\n  {a.link}")
    else:
        lines.append("No security item about your stack in this window.")

    blocks = country_sections(groups)
    lines.append("\n##### EUROPEAN FOCUS (IBM FOOTPRINT) #####")
    if blocks:
        for code, items in blocks:
            info = COUNTRIES[code]
            lines.append(f"\n-- {info['flag']} {info['name']} ({len(items)}) --")
            for a in items:
                lines.append(f"- {_badges(a)} {a.title} ({a.source})\n  {a.link}")
    else:
        lines.append("No item mentioned an IBM country in this window.")
    if SHOW_COUNTRY_LINKS:
        lines.append("\n##### NATIONAL CERT & TRUSTED SOURCES #####")
        for code, info in COUNTRIES.items():
            lines.append(f"{info['flag']} {info['name']} — {_country_links_text(info)}")

    if vendors:
        lines.append(f"\n##### EXPLOITED BY VENDOR ({VENDORS_DAYS} D, KEV — NOT ATTACK COUNTS) #####")
        lines.append(" · ".join(_vendor_line(f) for f in vendors))
    if stats:
        lines.append("\n##### TREND (previous 7 days) #####\n" + trend_line(stats))
    lines.append("\n" + "-" * 58)
    lines.append("Generated automatically by Nours_sec_bot")
    return "\n".join(lines)


# --- Envoi -------------------------------------------------------------------
def validate_config() -> tuple[str, str, str]:
    missing = [k for k in ("EMAIL_USER", "EMAIL_PASSWORD", "RECIPIENT_EMAIL") if not os.environ.get(k)]
    if missing:
        raise SystemExit(f"Missing environment variable(s): {', '.join(missing)}")
    sender = os.environ["EMAIL_USER"].strip()
    recipient = os.environ["RECIPIENT_EMAIL"].strip()
    for value in (sender, recipient):
        if "\r" in value or "\n" in value:
            raise SystemExit("Invalid e-mail address: line breaks are forbidden")
    return sender, os.environ["EMAIL_PASSWORD"], recipient


def _mime_part(body: str, subtype: str) -> MIMEText:
    """Partie MIME du message.

    En 8bit les octets UTF-8 partent tels quels ; en base64 (défaut de Python) ils sont réencodés
    et le message final pèse ~40 % de plus. Gmail accepte les deux (8BITMIME).
    """
    if EMAIL_ENCODING == "base64":
        return MIMEText(body, subtype, "utf-8")
    charset = Charset("utf-8")
    charset.body_encoding = None   # None = pas d'encodage -> Content-Transfer-Encoding: 8bit
    return MIMEText(body, subtype, charset)


def build_message(sender: str, recipient: str, subject: str,
                  html_body: str, text_body: str) -> MIMEMultipart:
    """Construit le message complet (séparé de l'envoi pour pouvoir le mesurer)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = subject, sender, recipient
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="noursecbot.local")
    msg.attach(_mime_part(text_body, "plain"))
    msg.attach(_mime_part(html_body, "html"))  # le HTML en dernier = version préférée
    return msg


def send_email(config: tuple[str, str, str], subject: str, html_body: str, text_body: str) -> None:
    sender, password, recipient = config
    msg = build_message(sender, recipient, subject, html_body, text_body)

    if SMTP_SECURITY not in ("ssl", "starttls"):
        log.warning("SMTP_SECURITY=%r unknown: using SSL", SMTP_SECURITY)

    context = ssl.create_default_context()
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            if SMTP_SECURITY == "starttls":
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                    server.starttls(context=context)
                    server.login(sender, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30, context=context) as server:
                    server.login(sender, password)
                    server.send_message(msg)
            log.info("E-mail sent successfully.")
            return
        except smtplib.SMTPAuthenticationError:
            log.error("SMTP authentication refused: check EMAIL_USER / EMAIL_PASSWORD "
                      "(Gmail app password)")
            raise
        except (smtplib.SMTPException, OSError) as exc:
            last_error = exc
            log.warning("E-mail delivery: attempt %d/3 failed (%s)", attempt, exc)
            if attempt < 3:
                time.sleep(5 * attempt)
    if last_error is not None:
        raise last_error


# --- Programme principal -----------------------------------------------------
def group_articles(results) -> tuple[dict[str, list[Article]], list[str]]:
    """Déduplique (liens et CVE) et regroupe par source. Retourne (groupes, liens_à_mémoriser).

    Un article dont TOUTES les CVE ont déjà été montrées n'est pas affiché de nouveau : sa source est
    ajoutée à « Also covered by » sur l'article conservé. Son lien est quand même mémorisé
    (sinon il reviendrait demain), car l'information a bien été livrée.
    """
    groups: dict[str, list[Article]] = {}
    new_links: list[str] = []
    seen_links: set[str] = set()
    cve_to_article: dict[str, Article] = {}

    for articles, _ in results:
        unique = []
        for a in articles:
            if a.link in seen_links:  # même lien publié par deux sources
                continue
            seen_links.add(a.link)
            new_links.append(a.link)
            cves = set(a.cves)
            if cves and cves.issubset(cve_to_article):
                target = cve_to_article[sorted(cves)[0]]
                if a.source != target.source and all(s != a.source for s, _ in target.also_covered):
                    target.also_covered.append((a.source, a.link))
                if "⚡" in a.tags and "⚡" not in target.tags:
                    # l'article fusionné signalait une campagne active : l'article conservé en hérite
                    target.tags = f"{target.tags} ⚡".strip()
                    target.score += 3
                    target.severity = severity_badge(target.score)
                continue
            for c in cves:
                cve_to_article.setdefault(c, a)
            unique.append(a)
        if unique:
            groups[unique[0].source] = unique
    return groups, new_links


def main() -> int:
    config = validate_config()  # échoue tout de suite si un secret manque
    now = datetime.now(TZ)
    today = now.date().isoformat()
    previous = load_seen_links()
    seen = set(previous)
    since = datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)
    session = create_session()
    conn = open_db()

    # Garde de redondance : si le rapport du jour est déjà parti (créneaux précédents), on s'arrête
    # ici, avant toute collecte. FORCE_VEILLE=1 permet de passer outre (test ou envoi manuel voulu).
    if not FORCE_VEILLE and meta_get(conn, META_DERNIERE_VEILLE) == today:
        log.info("Daily report already sent on %s: nothing to do.", today)
        if conn is not None:
            conn.close()  # sortie anticipée : la connexion ne passe pas par le finally
        return 0

    try:
        try:
            results = [collect_cisa_kev(session, seen)]
        except Exception as exc:  # noqa: BLE001 - KEV ne doit pas empêcher les RSS
            log.exception("CISA KEV: unexpected failure")
            results = [([], f"CISA KEV: unexpected error ({type(exc).__name__})")]
        try:
            results.append(collect_github_advisories(session, since))
        except Exception as exc:  # noqa: BLE001
            log.exception("GitHub Advisory: unexpected failure")
            results.append(([], f"GitHub Advisory: unexpected error ({type(exc).__name__})"))
        try:
            results.append(collect_ransomware_victims(session, since))
        except Exception as exc:  # noqa: BLE001
            log.exception("%s: unexpected failure", SOURCE_RANSOMWARE_API)
            results.append(([], f"{SOURCE_RANSOMWARE_API}: unexpected error ({type(exc).__name__})"))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results += list(pool.map(
                lambda s: collect_source(s, since, seen), RSS_SOURCES))

        errors = [err for _, err in results if err]
        groups, new_links = group_articles(results)
        sync_kev(conn, KEV_VULNS)

        # Enrichissements optionnels : une panne ne doit jamais empêcher l'envoi du rapport
        infos: dict[str, dict] = {}
        try:
            infos = enrich(session, groups, load_cvss_cache(conn))
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS/CVSS enrichment skipped: %s", exc)
        groups = dict(sorted(groups.items(), key=lambda kv: CATEGORY_ORDER.index(kv[1][0].category)))

        reminders: list[dict] = []
        vendors: list[dict] = []
        try:
            already_shown = {c for items in groups.values() for a in items for c in a.cves}
            reminders = kev_reminders(conn, session, today, already_shown)
            vendors = top_vendors(KEV_VULNS, today)
        except Exception as exc:  # noqa: BLE001
            log.warning("Reminders / vendor ranking skipped: %s", exc)

        stats = weekly_stats(conn, today)

        # Journal des scores : sert à ajuster les pondérations au fil des jours
        for items in groups.values():
            for a in items:
                if a.score > 0:
                    m = _metrics(a)
                    log.info("  score %2d %-2s [%s] %s%s", a.score, a.severity, a.source,
                             a.title[:90], f" ({m})" if m else "")

        if not groups and not errors:
            log.info("Nothing new: no e-mail sent.")
            return 0

        subject = f"🛡️ Cyber security watch — {now:%d/%m/%Y}"
        totals = compute_totals(groups)
        if totals["critical"]:
            subject += f" · 🔴 {totals['critical']} critical"
        if totals["campaigns"]:
            subject += f" · ⚡ {totals['campaigns']} campaign(s)"

        email_limit = MAX_EMAIL_ARTICLES
        html_report = render_html(groups, errors, stats, reminders, vendors,
                                  max_articles=email_limit)
        text_report = render_text(groups, errors, stats, reminders, vendors,
                                  max_articles=email_limit)
        html_size = len(html_report.encode("utf-8"))
        text_size = len(text_report.encode("utf-8"))
        # Si le message reste trop lourd, réduire par petits paliers (-10 %) plutôt que de moitié :
        # un jour chargé ne doit pas faire chuter le rapport à 60 articles.
        while (MAX_EMAIL_BYTES > 0 and html_size + text_size > MAX_EMAIL_BYTES
               and email_limit > 40):
            email_limit = max(40, email_limit - max(1, email_limit // 10))
            log.warning("Report of %d KB: reducing to %d items",
                        (html_size + text_size) // 1000, email_limit)
            html_report = render_html(groups, errors, stats, reminders, vendors,
                                      max_articles=email_limit)
            text_report = render_text(groups, errors, stats, reminders, vendors,
                                      max_articles=email_limit)
            html_size = len(html_report.encode("utf-8"))
            text_size = len(text_report.encode("utf-8"))
        log.info("Report size: %.1f KB HTML + %.1f KB text (%d items max)",
                 html_size / 1024, text_size / 1024, email_limit)
        if MAX_EMAIL_BYTES > 0 and html_size + text_size > MAX_EMAIL_BYTES:
            log.warning("Report of %d KB: Gmail truncation risk",
                        (html_size + text_size) // 1000)

        send_email(config, subject, html_report, text_report)
        meta_set(conn, META_DERNIERE_VEILLE, today)

        # On ne mémorise qu'APRÈS un envoi réussi : si l'envoi échoue, rien n'est perdu.
        all_links = {a.link for items in groups.values() for a in items}
        shown_links = {a.link for items in limit_for_email(groups, email_limit).values()
                       for a in items}
        shown_links |= {a.link for a in top_priorities(groups)}
        hidden = all_links - shown_links  # coupés par le plafond : ils pourront revenir
        save_seen_links(previous, [link for link in new_links if link not in hidden])
        store_stats(conn, groups, infos, today)

        # Code de sortie non nul si la veille est trop dégradée : le run apparaît en rouge.
        total_sources = len(RSS_SOURCES) + EXTRA_SOURCES
        sources_ok = total_sources - len(errors)
        if sources_ok == 0:
            log.error("No reachable source")
            return 1
        if len(errors) > total_sources * 0.3:
            log.error("%d/%d sources in error: degraded watch", len(errors), total_sources)
            return 1
        if any(err.startswith("CISA KEV") for err in errors):
            log.error("CISA KEV unavailable: degraded watch")
            return 1
        return 0
    finally:
        if conn is not None:
            conn.close()


# --- Mode alerte : e-mail immédiat pour une faille ou une attaque majeure ---
# Le rapport quotidien reste le seul e-mail « normal ». Ce mode (MODE_ALERTE=1 ou --alerte), lancé
# toutes les quelques heures par un second workflow, n'écrit que s'il trouve un article dont le
# score atteint ALERT_THRESHOLD et qui n'a pas déjà été signalé. Il utilise son propre fichier d'état
# (liens + CVE déjà signalés) : IGNORE_SEEN et seen.json ne le concernent pas.
ALERT_FILE = "alertes_envoyees.json"
ALERT_MAX_KEYS = 1500
ALERT_THRESHOLD = _env_int("ALERT_THRESHOLD", 14, 1, "SEUIL_ALERTE")
# Seuil abaissé pour ta stack : une faille sur Box, Slack, Teams ou Outlook est signalée plus tôt.
ALERT_STACK_THRESHOLD = _env_int("ALERT_STACK_THRESHOLD", 5, 1)
ALERT_WINDOW_HOURS = _env_int("ALERT_WINDOW_HOURS", 8, 1, "ALERTE_FENETRE_HEURES")
ALERT_MAX = _env_int("ALERT_MAX", 5, 1, "ALERTE_MAX")   # alertes par e-mail ; le reste part au passage suivant
ALERT_MODE = "--alerte" in sys.argv[1:] or _env_bool("MODE_ALERTE", False)


def load_alert_state() -> tuple[list[str], bool]:
    """(clés déjà signalées dans l'ordre, fichier lisible ?). Un fichier absent ou illisible
    déclenche l'amorçage : on mémorise l'existant sans envoyer de rafale d'e-mails."""
    try:
        data = json.loads(Path(ALERT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], False
    if not isinstance(data, list):
        return [], False
    return [str(x) for x in data], True


def _alert_keys(a: Article) -> list[str]:
    return [a.link] + [link for _, link in a.also_covered] + [f"cve:{c}" for c in a.cves]


def save_alert_state(previous: list[str], articles: list[Article]) -> None:
    known = set(previous)
    keys = list(previous)
    for a in articles:
        for key in _alert_keys(a):
            if key not in known:
                known.add(key)
                keys.append(key)
    _write_json_atomic(ALERT_FILE, keys[-ALERT_MAX_KEYS:])


def already_alerted(a: Article, known: set[str]) -> bool:
    if a.link in known:
        return True
    return bool(a.cves) and all(f"cve:{c}" in known for c in a.cves)


def _alert_floor(a: Article) -> int:
    """Seuil d'alerte applicable à un article : plus bas s'il concerne ta stack."""
    return ALERT_STACK_THRESHOLD if a.stack else ALERT_THRESHOLD


def preselect(groups: dict[str, list[Article]], known: set[str]) -> dict[str, list[Article]]:
    """Garde les articles qui pourraient atteindre le seuil une fois EPSS/CVSS ajoutés
    (évite des appels NVD inutiles à chaque passage)."""
    margin = enrichment_bonus(1.0, 10.0)
    kept: dict[str, list[Article]] = {}
    for source, items in groups.items():
        selected = [a for a in items
                    if a.score + margin >= _alert_floor(a) and not already_alerted(a, known)]
        if selected:
            kept[source] = selected
    return kept


def choose_alerts(groups: dict[str, list[Article]], known: set[str]) -> list[Article]:
    """Articles majeurs (score >= seuil) pas encore signalés, du plus grave au moins grave."""
    selected = [a for items in groups.values() for a in items
                if a.score >= _alert_floor(a) and not already_alerted(a, known)]
    selected.sort(key=lambda a: (a.score, a.date), reverse=True)
    return selected


def render_alert(articles: list[Article], remaining: int) -> tuple[str, str, str]:
    """(sujet, html, texte) de l'e-mail d'alerte."""
    def clean(txt: str) -> str:
        return " ".join(str(txt).split())  # pas de retour à la ligne dans un en-tête ou une ligne

    subject = f"🚨 Cyber alert: {clean(articles[0].title)[:110]}"
    if len(articles) > 1:
        subject += f" (+{len(articles) - 1})"
    blocks_html, blocks_text = [], []
    for a in articles:
        badges, metrics = _badges(a), _metrics(a)
        when = a.date.astimezone(TZ).strftime("%d/%m %H:%M")
        stack_label = "Stack: " + ", ".join(a.stack) if a.stack else ""
        details = " · ".join(x for x in (a.source, when, metrics, stack_label) if x)
        excerpt = clean(a.detail)[:400]
        link_ok = a.link.startswith(("http://", "https://"))
        title_html = html.escape(clean(a.title))
        if link_ok:
            title_html = (f'<a href="{html.escape(a.link, quote=True)}" target="_blank" '
                          f'rel="noopener noreferrer">{title_html}</a>')
        also_html = ", ".join(
            f'<a href="{html.escape(link, quote=True)}" target="_blank" rel="noopener noreferrer">'
            f"{html.escape(src)}</a>"
            for src, link in a.also_covered if link.startswith(("http://", "https://")))
        blocks_html.append(
            '<div style="margin:0 0 16px;padding:12px;border-left:4px solid #c0392b;background:#fdf2f0">'
            f'<div style="font-size:16px;font-weight:bold">{html.escape(badges)} {title_html}</div>'
            f'<div style="font-size:12px;color:#555;margin-top:4px">{html.escape(details)}</div>'
            + (f'<div style="margin-top:6px;font-size:13px">{html.escape(excerpt)}</div>' if excerpt else "")
            + (f'<div style="margin-top:6px;font-size:12px">Also covered by: {also_html}</div>'
               if also_html else "")
            + "</div>")
        blocks_text.append(
            f"{badges} {clean(a.title)}\n  {details}\n  {a.link}"
            + (f"\n  {excerpt}" if excerpt else "")
            + (f"\n  Also covered by: {', '.join(f'{src} ({link})' for src, link in a.also_covered)}"
               if a.also_covered else ""))
    # Le seuil affiché doit refléter celui qui a réellement déclenché l'alerte.
    seuil = f"score ≥ {ALERT_THRESHOLD}"
    if any(a.stack for a in articles):
        seuil += f", or ≥ {ALERT_STACK_THRESHOLD} for your stack"
    footer = f"Immediate alert ({seuil}). The full report comes with the daily watch."
    if remaining:
        footer += f" {remaining} more alert(s) will follow in a later e-mail."
    signature = (
        '<div style="margin-top:20px;padding:10px;background:#f8f9fa;'
        'border-top:3px solid #d9534f;text-align:center">'
        '<p style="margin:0;font-size:14px;color:#333">Generated automatically by '
        '<b style="color:#d9534f;font-size:17px">Nours_sec_bot</b></p></div>'
    )
    html_body = (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:680px;margin:auto">'
        '<h2 style="color:#c0392b;margin:0 0 12px">🚨 Cyber security alert</h2>'
        + "".join(blocks_html)
        + f'<p style="font-size:12px;color:#777">{html.escape(footer)}</p>'
        + signature + "</div>")
    text_body = ("CYBER SECURITY ALERT\n\n" + "\n\n".join(blocks_text)
                 + f"\n\n{footer}\n\n" + "-" * 58 + "\nGenerated automatically by Nours_sec_bot\n")
    return subject, html_body, text_body


def main_alert() -> int:
    config = validate_config()
    previous, existed = load_alert_state()
    known = set(previous)
    since = datetime.now(timezone.utc) - timedelta(hours=ALERT_WINDOW_HOURS)
    session = create_session()
    try:
        results = [collect_cisa_kev(session, set())]
    except Exception as exc:  # noqa: BLE001 - KEV ne doit pas empêcher les RSS
        log.exception("CISA KEV: unexpected failure")
        results = [([], f"CISA KEV: unexpected error ({type(exc).__name__})")]
    try:
        results.append(collect_github_advisories(session, since))
    except Exception as exc:  # noqa: BLE001
        log.exception("GitHub Advisory: unexpected failure")
        results.append(([], f"GitHub Advisory: unexpected error ({type(exc).__name__})"))
    try:
        results.append(collect_ransomware_victims(session, since))
    except Exception as exc:  # noqa: BLE001
        log.exception("%s: unexpected failure", SOURCE_RANSOMWARE_API)
        results.append(([], f"{SOURCE_RANSOMWARE_API}: unexpected error ({type(exc).__name__})"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results += list(pool.map(lambda s: collect_source(s, since, set()), RSS_SOURCES))

    errors = [err for _, err in results if err]
    groups, _ = group_articles(results)
    # Le rapport quotidien enregistre ; ici on ne fait que lire le cache CVSS.
    candidates = preselect(groups, known)
    if candidates:
        conn = open_db()
        try:
            enrich(session, candidates, load_cvss_cache(conn))
        except Exception as exc:  # noqa: BLE001 - sans EPSS/CVSS on garde le score de base
            log.warning("EPSS/CVSS enrichment skipped: %s", exc)
        finally:
            if conn is not None:
                conn.close()

    majors = choose_alerts(candidates, known)
    log.info("Alert: %d candidate(s) examined, %d major(s) not yet reported (threshold %d)",
             sum(len(x) for x in candidates.values()), len(majors), ALERT_THRESHOLD)
    for a in majors:
        log.info("  major %2d [%s] %s", a.score, a.source, a.title[:90])
    if not existed:
        save_alert_state(previous, majors)
        log.info("Bootstrap: %d element(s) remembered without sending", len(majors))
        return 0
    if not majors:
        return 1 if len(errors) >= len(RSS_SOURCES) + 1 else 0
    to_send = majors[:ALERT_MAX]
    subject, html_body, text_body = render_alert(to_send, len(majors) - len(to_send))
    send_email(config, subject, html_body, text_body)
    save_alert_state(previous, to_send)  # après l'envoi : un échec SMTP sera retenté au passage suivant
    return 0


if __name__ == "__main__":
    if "--check-feeds" in sys.argv:
        sys.exit(check_feeds())
    if "--check-links" in sys.argv or "--check-country-links" in sys.argv:
        sys.exit(check_country_links())
    sys.exit(main_alert() if ALERT_MODE else main())
