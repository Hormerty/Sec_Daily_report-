"""Offline checks for veille.py (no network access needed)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Stubs minimaux : le module importe feedparser/requests/urllib3, mais les tests
# n'appellent aucune fonction réseau.
feedparser = types.ModuleType("feedparser")
feedparser.parse = lambda *a, **k: None
sys.modules["feedparser"] = feedparser

requests = types.ModuleType("requests")


class RequestException(Exception):
    pass


class Session:
    pass


requests.RequestException = RequestException
requests.Session = Session
requests.post = lambda *a, **k: None
sys.modules["requests"] = requests

adapters = types.ModuleType("requests.adapters")


class HTTPAdapter:
    def __init__(self, *a, **k):
        pass


adapters.HTTPAdapter = HTTPAdapter
sys.modules["requests.adapters"] = adapters

urllib3 = types.ModuleType("urllib3")
sys.modules["urllib3"] = urllib3
util = types.ModuleType("urllib3.util")
sys.modules["urllib3.util"] = util
retry = types.ModuleType("urllib3.util.retry")


class Retry:
    def __init__(self, *a, **k):
        pass


retry.Retry = Retry
sys.modules["urllib3.util.retry"] = retry

chemin = Path(__file__).with_name("veille.py")
spec = importlib.util.spec_from_file_location("veille_under_test", chemin)
v = importlib.util.module_from_spec(spec)
sys.modules["veille_under_test"] = v
assert spec.loader is not None
spec.loader.exec_module(v)

# --- CVE / score -------------------------------------------------------------
assert v.extract_cves("CVE-2024-1234") == {"CVE-2024-1234"}
assert v.extract_cves("CVE‑2024‑12345") == {"CVE-2024-12345"}
assert v.extract_cves("CVE-2024-123") == set()
assert v.extract_cves("cve-2023-1234 et CVE-2023-1234") == {"CVE-2023-1234"}

assert v.compute_criticality("CVE-2024-1234 is not exploited in the wild")[0] == 3, \
    v.compute_criticality("CVE-2024-1234 is not exploited in the wild")
assert v.compute_criticality("CVE-2024-1234 : aucune exploitation active observée")[0] == 3
assert v.compute_criticality("CVE-2024-1234 : aucun zero-day utilisé")[0] == 3
assert v.compute_criticality("CVE-2024-1234 : pas de ransomware observé")[0] == 3
assert v.compute_criticality("CVE-2024-1234 actively exploited in the wild")[0] >= 8
assert v.compute_criticality("CVE-2024-1234 exploitée activement dans la nature")[0] >= 8

assert not v.is_relevant("administration système et dossier partagé")
assert v.is_relevant("CVE-2024-1234 : faille critique dans Exchange")

assert "T1566" in v.detect_ttps("phishing campaign with ransomware")
assert "T1486" in v.detect_ttps("phishing campaign with ransomware")
assert v.detect_actors("Midnight Blizzard cible Microsoft") == ("APT29",)

# --- Pays de l'empreinte IBM -------------------------------------------------
assert "DE" in v.detect_countries("CERT-Bund warns about Exchange in Deutschland")
assert "BE" in v.detect_countries("Le CCB alerte sur une faille")
assert "EU" in v.detect_countries("The European Commission proposes a NIS2 update")
assert v.detect_countries("Lorem ipsum dolor sit amet") == ()
for code, info in v.COUNTRIES.items():
    assert info["flag"] and info["name"] and info["links"], code
    assert all(url.startswith("https://") for _, url in info["links"]), code

# --- Ta stack : Box, Slack, Teams, Outlook -----------------------------------
assert v.detect_stack("Box Drive vulnerability allows local privilege escalation") == ("Box",)
assert v.detect_stack("A Slack phishing campaign hits thousands") == ("Slack",)
assert v.detect_stack("Microsoft Teams used to deliver malware") == ("Teams",)
assert v.detect_stack("Outlook zero-day exploited in the wild") == ("Outlook",)
# Les gardes doivent écarter les faux positifs anglais
assert v.detect_stack("This model is a black box") == ()
assert v.detect_stack("CSS box model explained") == ()
assert v.detect_stack("security teams responded quickly") == ()
print("Stack detection: OK")

stack_art = v.Article(source="X", title="Box Drive flaw exploited", link="https://e/box",
                      date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                      score=v.ALERT_STACK_THRESHOLD + 1, stack=("Box",))
plain_art = v.Article(source="X", title="Random flaw", link="https://e/plain",
                      date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                      score=v.ALERT_STACK_THRESHOLD + 1)
assert v.choose_alerts({"X": [stack_art]}, set()) == [stack_art]   # seuil abaissé
assert v.choose_alerts({"X": [plain_art]}, set()) == []            # seuil normal
html_stack = v.render_html({"X": [stack_art]}, [])
assert "Your stack (Box · Slack · Teams · Outlook · Microsoft 365)" in html_stack
assert "Box Drive flaw exploited" in html_stack
print("Stack watch (section + alert threshold): OK")

# Une annonce produit Microsoft 365 ne doit PAS entrer dans la rubrique ;
# un article qui porte un signal sécurité, si.
annonce = v.Article(source="Clubic", title="Microsoft 365 Copilot gets a new feature",
                    link="https://e/annonce", date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                    score=4, stack=("Microsoft 365",))
incident = v.Article(source="BleepingComputer",
                     title="Hackers exploit an Outlook flaw in Microsoft 365 tenants",
                     link="https://e/incident", date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                     score=9, cves=("CVE-2026-4242",), stack=("Outlook", "Microsoft 365"))
assert v.stack_sections({"A": [annonce]}) == []
assert [n for n, _ in v.stack_sections({"B": [incident]})] == ["Outlook", "Microsoft 365"]
print("Stack watch (produit vs incident): OK")


# --- Collecte RSS avec un flux factice --------------------------------------
class ReponseFactice:
    content = b"<rss></rss>"

    def raise_for_status(self):
        return None


class SessionFactice:
    def get(self, *a, **k):
        return ReponseFactice()


entree = {
    "link": "/article/1",
    "title": None,
    "published_parsed": datetime(2026, 10, 25, 8, 0, tzinfo=timezone.utc).timetuple(),
    "summary": "<p>CVE-2024-1234 actively exploited in the wild</p>",
    "tags": None,
    "content": [{"value": "contenu additionnel"}],
}
sans_lien = dict(entree, link="")
lien_douteux = dict(entree, link="javascript:alert(1)")
date_invalide = dict(entree, published_parsed=(2026, 13, 1, 0, 0, 0, 0, 0, 0))
flux = types.SimpleNamespace(bozo=False, entries=[entree, sans_lien, lien_douteux, date_invalide])
ancien_parse = v.feedparser.parse
v.feedparser.parse = lambda contenu: flux
try:
    articles, erreur = v.collect_rss(
        SessionFactice(),
        {"name": "Test", "url": "https://example.com/feed", "category": v.ALERTS},
        datetime(2026, 10, 24, tzinfo=timezone.utc),
        set(),
    )
finally:
    v.feedparser.parse = ancien_parse
assert erreur is None, erreur
assert len(articles) == 1, len(articles)
assert articles[0].link == "https://example.com/article/1", articles[0].link
assert articles[0].title == "Untitled item", articles[0].title
assert articles[0].score >= 8, articles[0].score
assert "CVE-2024-1234" in articles[0].cves
print("Fake RSS collection: OK")

# Une source nationale rattache son pays même si le texte ne le nomme pas
source_de = {"name": "BSI", "url": "https://example.com/feed", "category": v.ALERTS, "country": "DE"}
v.feedparser.parse = lambda contenu: flux
try:
    articles_de, _ = v.collect_rss(
        SessionFactice(), source_de, datetime(2026, 10, 24, tzinfo=timezone.utc), set())
finally:
    v.feedparser.parse = ancien_parse
assert articles_de[0].countries[0] == "DE", articles_de[0].countries
assert "🇩🇪" in articles_de[0].tags, articles_de[0].tags
print("Country tagging from source: OK")


# --- GitHub Advisory (API) factice ------------------------------------------
class ReponseGitHub:
    def raise_for_status(self):
        return None

    def json(self):
        return [{
            "ghsa_id": "GHSA-test-1234",
            "cve_id": "CVE-2026-1234",
            "html_url": "https://github.com/advisories/GHSA-test-1234",
            "summary": "RCE critique dans un produit",
            "severity": "critical",
            "published_at": "2026-10-25T10:00:00Z",
            "cvss": {"score": 9.8},
        }]


class SessionGitHub:
    def get(self, *a, **k):
        return ReponseGitHub()


articles_gh, erreur_gh = v.collect_github_advisories(
    SessionGitHub(), datetime(2026, 10, 24, tzinfo=timezone.utc))
assert erreur_gh is None, erreur_gh
assert len(articles_gh) == 1, len(articles_gh)
assert articles_gh[0].source == "GitHub Advisory"
assert "CVE-2026-1234" in articles_gh[0].cves
print("Fake GitHub Advisory: OK")

# Rapport glissant : par défaut, un lien déjà vu reste inclus.
v.feedparser.parse = lambda contenu: flux
try:
    deja_vus = {"https://example.com/article/1"}
    articles_vus, _ = v.collect_rss(
        SessionFactice(),
        {"name": "Test", "url": "https://example.com/feed", "category": v.ALERTS},
        datetime(2026, 10, 24, tzinfo=timezone.utc),
        deja_vus,
    )
    assert len(articles_vus) == 1, len(articles_vus)
    ancien_ignore = v.IGNORE_SEEN
    v.IGNORE_SEEN = False
    articles_ignores, _ = v.collect_rss(
        SessionFactice(),
        {"name": "Test", "url": "https://example.com/feed", "category": v.ALERTS},
        datetime(2026, 10, 24, tzinfo=timezone.utc),
        deja_vus,
    )
    v.IGNORE_SEEN = ancien_ignore
    assert len(articles_ignores) == 0, len(articles_ignores)
finally:
    v.feedparser.parse = ancien_parse
print("Rolling 48 h window: OK")

# --- Plafond d'e-mail --------------------------------------------------------
def article(source: str, rang: int, tags: str = "", cves=()) -> v.Article:
    return v.Article(
        source=source,
        title=f"CVE-2026-{1000 + rang} : nouvelle faille critique dans un produit d'entreprise",
        link=f"https://example.com/{source}/{rang}",
        date=datetime(2026, 10, 25, tzinfo=timezone.utc),
        tags=tags,
        cves=cves,
    )


groupes = {f"S{i}": [article(f"S{i}", j) for j in range(10)] for i in range(5)}
limites = v.limit_for_email(groupes, 12)
assert sum(len(x) for x in limites.values()) == 12
assert all(len(x) >= 2 for x in limites.values()), limites

# --- Rendu / échappement -----------------------------------------------------
malveillant = v.Article(
    source="X",
    title="<script>alert(1)</script>",
    link="https://example.com/?a=1&b=2",
    date=datetime(2026, 10, 25, tzinfo=timezone.utc),
    tags="🔥",
    cves=("CVE-2024-1234",),
    ttps=("T1566",),
    actors=("APT29",),
    countries=("DE",),
    stack=("Box",),
)
html = v.render_html({"X": [malveillant]}, [])
assert "<script>" not in html
assert "&lt;script&gt;" in html
assert "&amp;b=2" in html
assert 'rel="noopener noreferrer"' in html
assert "T1566" in html
assert "APT29" in html
assert "European focus (IBM footprint)" in html
assert "🇩🇪" in html

malveillant.also_covered = [("Y", "https://example.com/y")]
html_aussi = v.render_html({"X": [malveillant]}, [])
assert 'href="https://example.com/y"' in html_aussi
assert "Also covered by" in html_aussi

texte = v.render_text({"X": [malveillant]}, [])
assert "Titre" not in texte  # le titre malveillant est bien celui de l'article
assert "<script>" in texte  # en texte brut, pas d'échappement HTML nécessaire

# --- Métriques ---------------------------------------------------------------
a1 = article("A", 1, tags="🔥", cves=("CVE-2024-1234",))
a2 = article("B", 2, tags="🔥", cves=("CVE-2024-1234",))
compte = v.compute_totals({"A": [a1], "B": [a2]})
assert compte["cves_ransomware"] == 1, compte
assert compte["active_sources"] == 2
assert compte["total_sources"] == len(v.RSS_SOURCES) + v.EXTRA_SOURCES

# --- État atomique -----------------------------------------------------------
with tempfile.TemporaryDirectory() as dossier:
    v.SEEN_FILE = str(Path(dossier) / "seen.json")
    v.save_seen_links(["a"], ["b", "a"])
    contenu = json.loads(Path(v.SEEN_FILE).read_text(encoding="utf-8"))
    assert contenu == ["a", "b"], contenu

# --- Variables d'environnement ----------------------------------------------
os.environ["_TEST_ENV_INT"] = "12h"
assert v._env_int("_TEST_ENV_INT", 36) == 36
os.environ["_TEST_ENV_INT"] = "7"
assert v._env_int("_TEST_ENV_INT", 36) == 7
# Les anciens noms restent lus (rétro-compatibilité du workflow)
os.environ["_TEST_LEGACY"] = "72"
assert v._env_int("_TEST_MISSING", 48, 1, "_TEST_LEGACY") == 72
del os.environ["_TEST_LEGACY"]
assert v._env_bool("_TEST_BOOL", True, "_TEST_MISSING_BOOL") is True

# --- Taille du HTML avec un volume réaliste ---------------------------------
gros = {f"S{i}": [article(f"S{i}", j) for j in range(15)] for i in range(27)}
TAILLE_TEST = 160
html_gros = v.render_html(gros, [], max_articles=TAILLE_TEST)
taille_gros = len(html_gros.encode("utf-8"))
print(f"HTML {TAILLE_TEST} articles : {taille_gros / 1024:.1f} Ko")
assert taille_gros < 102_000, taille_gros

# --- Poids réel du message tel qu'il partirait (encodage compris) -----------
gros_html = v.render_html(gros, [], max_articles=TAILLE_TEST)
gros_texte = v.render_text(gros, [], max_articles=TAILLE_TEST)
message = v.build_message("bot@example.com", "dest@example.com", "test", gros_html, gros_texte)
poids = len(message.as_bytes())
cte = message.get_payload()[-1].get("Content-Transfer-Encoding")
print(f"Message sérialisé ({TAILLE_TEST} articles) : {poids / 1024:.1f} Ko, CTE={cte}")
assert cte == ("base64" if v.EMAIL_ENCODING == "base64" else "8bit"), cte
assert poids < 100_000, poids     # marge sous le seuil de troncature Gmail (~102 Ko)
print(f"Plafond de taille : {'désactivé' if v.MAX_EMAIL_BYTES == 0 else str(v.MAX_EMAIL_BYTES) + ' o'}")

# --- Pipeline principal (réseau et envoi simulés) ---------------------------
from unittest import mock

envoye = {}


def capture(config, subject, html_body, text_body):
    envoye.update(subject=subject, html=html_body, text=text_body)


kev_article = article("CISA KEV", 1, cves=("CVE-2024-1234",))
kev_article.title = "CVE-2024-1234 : test KEV"

with mock.patch.multiple(
    v,
    validate_config=lambda: ("bot@example.com", "secret", "dest@example.com"),
    create_session=lambda: object(),
    open_db=lambda: None,
    collect_cisa_kev=lambda session, seen: ([kev_article], None),
    collect_github_advisories=lambda session, since: ([], None),
    collect_ransomware_victims=lambda *a, **k: ([], None),
    collect_source=lambda source, since, seen: ([], None),
    enrich=lambda session, groups, cache: {},
    sync_kev=lambda conn, vulns: None,
    kev_reminders=lambda *a, **k: [],
    top_vendors=lambda *a, **k: [],
    weekly_stats=lambda *a, **k: None,
    send_email=capture,
    save_seen_links=lambda *a: None,
    store_stats=lambda *a: None,
):
    code = v.main()

assert code == 0, code
assert "Cyber security watch" in envoye["subject"]
assert "CVE-2024-1234" in envoye["html"]
assert "known-exploited-vulnerabilities-catalog" in envoye["html"]   # en-tête de source cliquable
print("Nominal pipeline (simulated): OK")

# --- Pipeline dégradé (toutes les sources en erreur) -----------------------
with mock.patch.multiple(
    v,
    validate_config=lambda: ("bot@example.com", "secret", "dest@example.com"),
    create_session=lambda: object(),
    open_db=lambda: None,
    collect_cisa_kev=lambda session, seen: ([], "CISA KEV : boom"),
    collect_github_advisories=lambda session, since: ([], "GitHub Advisory : boom"),
    collect_ransomware_victims=lambda *a, **k: ([], "Ransomware.live (victims) : boom"),
    collect_source=lambda source, since, seen: ([], f"{source['name']} : boom"),
    enrich=lambda session, groups, cache: {},
    sync_kev=lambda conn, vulns: None,
    kev_reminders=lambda *a, **k: [],
    top_vendors=lambda *a, **k: [],
    weekly_stats=lambda *a, **k: None,
    send_email=capture,
    save_seen_links=lambda *a: None,
    store_stats=lambda *a: None,
):
    code_degrade = v.main()

assert code_degrade == 1, code_degrade
print("Degraded pipeline (simulated): OK")


# --- Envoi SMTP factice ------------------------------------------------------
class FauxSMTP:
    message = None

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login(self, *a, **k):
        return None

    def send_message(self, message):
        FauxSMTP.message = message
        message.as_string()  # vérifie l'encodage des en-têtes (sujet avec emoji)


ancien_smtp = v.smtplib.SMTP_SSL
v.smtplib.SMTP_SSL = FauxSMTP
try:
    v.send_email(
        ("bot@example.com", "secret", "dest@example.com"),
        "🛡️ Test watch",
        "<p>html</p>",
        "texte",
    )
finally:
    v.smtplib.SMTP_SSL = ancien_smtp
assert FauxSMTP.message is not None
assert FauxSMTP.message["Message-ID"]
assert FauxSMTP.message["Date"]
print("Fake SMTP send: OK")


# --- Cache KEV de secours ----------------------------------------------------
class SessionEnPanne:
    def get(self, *a, **k):
        raise v.requests.RequestException("CISA indisponible")


with tempfile.TemporaryDirectory() as dossier:
    ancien_cache = v.KEV_CACHE_FILE
    v.KEV_CACHE_FILE = str(Path(dossier) / "kev_cache.json")
    try:
        v._write_kev_cache([{
            "cveID": "CVE-2024-1234",
            "dateAdded": datetime.now(timezone.utc).date().isoformat(),
            "vendorProject": "Test",
            "product": "Produit",
            "shortDescription": "Description",
            "knownRansomwareCampaignUse": "Unknown",
        }])
        assert v._read_kev_cache()[0]["cveID"] == "CVE-2024-1234"
        articles_kev, erreur_kev = v.collect_cisa_kev(SessionEnPanne(), set())
        assert erreur_kev is None, erreur_kev
        assert len(articles_kev) == 1, len(articles_kev)
        assert articles_kev[0].source == "CISA KEV"
    finally:
        v.KEV_CACHE_FILE = ancien_cache

print("KEV fallback cache: OK")


# --- Base SQLite -------------------------------------------------------------
with tempfile.TemporaryDirectory() as dossier:
    ancienne_db = v.DB_FILE
    v.DB_FILE = str(Path(dossier) / "stats.db")
    conn = v.open_db()
    try:
        assert conn is not None
        art = v.Article(
            source="S",
            title="CVE-2024-1234 : test",
            link="https://example.com/1",
            date=datetime(2026, 10, 25, tzinfo=timezone.utc),
            score=8,
            severity="🟠",
            cves=("CVE-2024-1234",),
        )
        v.store_stats(conn, {"S": [art]}, {"CVE-2024-1234": {"epss": 0.5, "cvss": 9.0}},
                      "2026-10-25")
        assert conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == 1
        ligne = conn.execute("SELECT cve, epss, cvss, kev FROM cves").fetchone()
        assert ligne == ("CVE-2024-1234", 0.5, 9.0, 0), ligne
        v.sync_kev(conn, [{
            "cveID": "CVE-2024-1234",
            "knownRansomwareCampaignUse": "Known",
        }])
        ligne = conn.execute("SELECT kev, ransomware FROM cves").fetchone()
        assert ligne == (1, 1), ligne
    finally:
        if conn is not None:
            conn.close()
        v.DB_FILE = ancienne_db

print("SQLite layer: OK")


# --- Statistiques hebdomadaires -------------------------------------------------
# Régression : la requête « source » utilisait la colonne vue_le (propre à la table cves) sur la
# table articles, qui s'appelle vu_le. SQLite levait « no such column » et la section Tendance
# disparaissait silencieusement du mail.
with tempfile.TemporaryDirectory() as dossier:
    ancienne_db = v.DB_FILE
    v.DB_FILE = str(Path(dossier) / "stats.db")
    conn = v.open_db()
    try:
        base = datetime(2026, 10, 29, tzinfo=timezone.utc)
        for i in range(3):
            jour = (base - timedelta(days=i)).date().isoformat()
            art = v.Article(source="S", title=f"t{i}", link=f"https://e/{i}",
                            date=base, severity="🟠")
            v.store_stats(conn, {"S": [art]}, {f"CVE-2026-{i}": {"epss": 0.5, "cvss": 9.0}}, jour)
        stats = v.weekly_stats(conn, base.date().isoformat())
        assert stats is not None, "weekly_stats ne doit pas renvoyer None"
        assert stats["active_days"] == 2, stats
        assert "items" in v.trend_line(stats)
    finally:
        conn.close()
        v.DB_FILE = ancienne_db
print("Weekly stats: OK")


# --- Garde anti-double-envoi (redondance de planification) -------------------
# Le workflow quotidien est planifié trois fois : si un créneau a déjà envoyé le rapport du jour,
# les suivants doivent s'arrêter avant toute collecte.
with tempfile.TemporaryDirectory() as dossier:
    ancienne_db = v.DB_FILE
    v.DB_FILE = str(Path(dossier) / "garde.db")
    try:
        conn = v.open_db()
        v.meta_set(conn, v.META_DERNIERE_VEILLE, datetime.now(v.TZ).date().isoformat())
        assert v.meta_get(conn, v.META_DERNIERE_VEILLE) is not None
        conn.close()

        envois = []
        with mock.patch.multiple(
            v,
            validate_config=lambda: ("bot@example.com", "secret", "dest@example.com"),
            load_seen_links=lambda: [],
            create_session=lambda: object(),
            send_email=lambda *a, **k: envois.append(1),
            collect_cisa_kev=lambda *a, **k: ([], None),
            collect_github_advisories=lambda *a, **k: ([], None),
            collect_ransomware_victims=lambda *a, **k: ([], None),
            collect_source=lambda *a, **k: ([], None),
        ):
            code = v.main()
        assert code == 0, code
        assert not envois, "un second envoi le meme jour ne doit pas partir"
    finally:
        v.DB_FILE = ancienne_db
print("Daily send guard: OK")


# --- Scoring des fuites de donnees et faux positifs de stack ----------------
# Ces deux garde-fous viennent d'une relecture externe : avant correction, une fuite de plusieurs
# millions de comptes valait 0, et « Cybersecurity Outlook 2027 » etait pris pour le client mail.
for titre in ("Capcom confirms data breach affecting 11.7 million accounts",
              "Quest Diagnostics data breach exposes patient records",
              "LiteLLM master key leaked"):
    score, _ = v.compute_criticality(titre)
    assert score >= v.IMPORTANT_THRESHOLD, (titre, score)

# Aucun badge sur une actualite anodine ni sur une etude de marche.
for titre in ("Microsoft announces new pricing for cloud services",
              "New report: state of cloud security 2027"):
    score, _ = v.compute_criticality(titre)
    assert score < v.IMPORTANT_THRESHOLD, (titre, score)

# Le produit reste detecte, l'etude de marche non.
assert "Outlook" not in v.detect_stack("Cybersecurity Outlook 2027")
assert "Outlook" not in v.detect_stack("Threat Outlook 2028")
assert "Outlook" in v.detect_stack("Outlook zero-day exploited in the wild")
assert "Outlook" in v.detect_stack("Microsoft Outlook RCE")
print("Breach scoring / stack noise: OK")


# --- Exploitation seule = pastille -------------------------------------------------
# « Actively exploited » valait 5, un point sous le seuil de 6 : sept articles reels (PHP2Shell,
# Drupal, ASA/FTD, VeloCloud) ressortaient sans marque alors qu'ils annoncaient l'exploitation.
for titre in ("CISA confirms PHP2Shell vulnerabilities now exploited in attacks",
              "Cisco Patches Actively Exploited ASA and FTD VPN Flaw That Can Crash Firewalls",
              "Drupal warns of critical Commerce Core flaw exploited in attacks"):
    score, _ = v.compute_criticality(titre)
    assert score >= v.IMPORTANT_THRESHOLD, (titre, score)
print("Exploitation badge: OK")


# --- Mode alerte -------------------------------------------------------------
alerte_subject, alerte_html, alerte_text = v.render_alert([malveillant], 2)
assert alerte_subject.startswith("🚨 Cyber alert:"), alerte_subject
assert "Cyber security alert" in alerte_html
assert "2 more alert(s)" in alerte_html
assert "Nours_sec_bot" in alerte_html          # la signature figure aussi dans l'alerte
assert alerte_text.startswith("CYBER SECURITY ALERT")
assert "Nours_sec_bot" in alerte_text
assert "Stack: Box" in alerte_html              # la stack est nommée dans l'alerte
assert v.ALERT_STACK_THRESHOLD == 5

a_cve = article("S", 1, cves=("CVE-2024-1",))
assert not v.already_alerted(a_cve, set())
assert v.already_alerted(a_cve, {a_cve.link})
assert v.already_alerted(a_cve, {"cve:CVE-2024-1"})
assert not v.already_alerted(a_cve, {"cve:CVE-2024-2"})

marge = v.enrichment_bonus(1.0, 10.0)
juste = article("S", 2)
juste.score = v.ALERT_THRESHOLD - marge
trop_bas = article("S", 3)
trop_bas.score = v.ALERT_THRESHOLD - marge - 1
assert v.preselect({"S": [juste, trop_bas]}, set()) == {"S": [juste]}

majeur = article("S", 4, cves=("CVE-2024-4",))
majeur.score = v.ALERT_THRESHOLD
assert v.choose_alerts({"S": [majeur]}, set()) == [majeur]
assert v.choose_alerts({"S": [majeur]}, {majeur.link}) == []

# Amorçage puis anti-doublon, sans envoi
with tempfile.TemporaryDirectory() as dossier:
    ancien_fichier = v.ALERT_FILE
    v.ALERT_FILE = str(Path(dossier) / "alertes_envoyees.json")
    envois: list[str] = []

    def capture_alerte(config, subject, html_body, text_body):
        envois.append(subject)

    nouveau = v.Article(source="CISA KEV", title="CVE-2026-9999 : Acme Router",
                        link="https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
                        date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                        score=20, severity="🔴", cves=("CVE-2026-9999",))
    try:
        with mock.patch.multiple(
            v,
            validate_config=lambda: ("bot@example.com", "secret", "dest@example.com"),
            create_session=lambda: object(),
            collect_cisa_kev=lambda session, seen: ([nouveau], None),
            collect_github_advisories=lambda session, since: ([], None),
            collect_ransomware_victims=lambda *a, **k: ([], None),
            collect_source=lambda source, since, seen: ([], None),
            enrich=lambda session, groups, cache: {},
            open_db=lambda: None,
            load_cvss_cache=lambda conn: {},
            send_email=capture_alerte,
        ):
            assert v.main_alert() == 0, "amorcage doit renvoyer 0"
            assert envois == [], envois            # amorçage : rien envoyé
            assert Path(v.ALERT_FILE).exists()
            assert v.main_alert() == 0
            assert envois == [], envois            # même alerte : aucun doublon
            autre = v.Article(source="CISA KEV", title="CVE-2027-0001 : Nouveau produit",
                              link="https://nvd.nist.gov/vuln/detail/CVE-2027-0001",
                              date=datetime(2026, 10, 25, tzinfo=timezone.utc),
                              score=21, severity="🔴", cves=("CVE-2027-0001",))
            with mock.patch.object(v, "collect_cisa_kev", lambda session, seen: ([autre], None)):
                assert v.main_alert() == 0
            assert len(envois) == 1, envois        # nouvelle faille majeure : 1 e-mail
            assert "CVE-2027-0001" in envois[0], envois[0]
    finally:
        v.ALERT_FILE = ancien_fichier

print("Alert mode (bootstrap + dedup + send): OK")

print("OK: all offline checks pass")
