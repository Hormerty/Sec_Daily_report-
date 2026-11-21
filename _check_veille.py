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
# L'en-tete se derive de la liste des produits : ajouter une stack ne doit pas casser ce test.
assert "Your stack (" + " · ".join(v.STACK_PRODUCTS) + ")" in html_stack, html_stack[:400]
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
assert articles[0].title == "CVE-2024-1234 actively exploited in the wild", articles[0].title
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
print("Rolling 27 h window: OK")

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
    collect_hibp=lambda *a, **k: ([], None),
    collect_euvd=lambda *a, **k: ([], None),
    collect_nvd_vendors=lambda *a, **k: ([], None),
    collect_metasploit_cves=lambda *a, **k: ([], None),
    fetch_mirage_stats=lambda *a, **k: {},
    collect_source=lambda source, since, seen: ([], None),
    enrich=lambda session, groups, cache, *a, **k: {},
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
    collect_hibp=lambda *a, **k: ([], "Have I Been Pwned : boom"),
    collect_euvd=lambda *a, **k: ([], "EUVD (ENISA) : boom"),
    collect_nvd_vendors=lambda *a, **k: ([], "NVD (éditeurs) : boom"),
    collect_metasploit_cves=lambda *a, **k: ([], "Metasploit (CVE armées) : boom"),
    fetch_mirage_stats=lambda *a, **k: {},
    collect_source=lambda source, since, seen: ([], f"{source['name']} : boom"),
    enrich=lambda session, groups, cache, *a, **k: {},
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
            collect_hibp=lambda *a, **k: ([], None),
            collect_euvd=lambda *a, **k: ([], None),
            collect_nvd_vendors=lambda *a, **k: ([], None),
            collect_metasploit_cves=lambda *a, **k: ([], None),
            fetch_mirage_stats=lambda *a, **k: {},
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


# --- Déduplication dark web ---------------------------------------------------
# L'API et RansomLook publient la même victime sous deux libellés et deux liens : le doublon
# doit disparaître, mais les victimes propres à RansomLook doivent survivre.
_maintenant = datetime.now(timezone.utc)


def _art(source, titre):
    return v.Article(source=source, title=titre, link="https://x/" + str(abs(hash(titre))),
                     date=_maintenant, category=v.DARKWEB)


_resultats = [
    ([_art(v.SOURCE_RANSOMWARE_API, "Astino Berhad — revendiqué par qilin")], None),
    ([_art("RansomLook", "Astino Berhad By qilin"),
      _art("RansomLook", "[disclosed]Namibian Force By leakeddata"),
      _art("RansomLook", "Translogwest By akira")], None),
]
_titres = [a.title for arts, _ in v.dedupe_ransomware(_resultats) for a in arts]
assert any("revendiqué" in t for t in _titres), _titres          # la version API est gardée
assert "Astino Berhad By qilin" not in _titres, _titres          # le doublon RansomLook disparaît
assert any("Namibian" in t for t in _titres), _titres            # les uniques survivent
assert any("Translogwest" in t for t in _titres), _titres
assert v.victim_key("X Y By z") == v.victim_key("X Y — revendiqué par z")
print("Ransomware dedup: OK")


# --- Jeton GitHub pour l'API Advisory -----------------------------------------
# Sans jeton, l'API plafonne a 60 requetes/heure et par IP, quota partage par tous les runners :
# la collecte echouait en silence. Le jeton doit partir en en-tete des qu'il est present.
_capture = {}


class _RepAdvisory:
    def raise_for_status(self):
        pass

    def json(self):
        return []


class _SessAdvisory:
    def get(self, url, params=None, timeout=None, headers=None):
        _capture["h"] = headers or {}
        return _RepAdvisory()


_jeton_initial = v.GITHUB_TOKEN
try:
    v.GITHUB_TOKEN = "ghs_test"
    v.collect_github_advisories(_SessAdvisory(), datetime.now(timezone.utc) - timedelta(days=1))
    assert _capture["h"].get("Authorization") == "Bearer ghs_test", _capture
    v.GITHUB_TOKEN = ""
    v.collect_github_advisories(_SessAdvisory(), datetime.now(timezone.utc) - timedelta(days=1))
    assert "Authorization" not in _capture["h"], _capture
finally:
    v.GITHUB_TOKEN = _jeton_initial
print("Advisory token: OK")


# --- Sources muettes ----------------------------------------------------------
# Un flux peut repondre et ne plus rien publier : le bandeau d'erreurs ne le voit pas.
assert v.silent_sources(None, datetime.now(timezone.utc)) == []

with tempfile.TemporaryDirectory() as _dossier:
    _ancienne_db = v.DB_FILE
    v.DB_FILE = str(Path(_dossier) / "silent.db")
    _conn = v.open_db()
    # Deux vraies sources : le calcul ignore desormais les noms absents du code, pour ne pas
    # signaler indefiniment une source retiree.
    _nom_recent = v.RSS_SOURCES[0]["name"]
    _nom_muet = v.RSS_SOURCES[1]["name"]
    try:
        _auj = datetime.now(timezone.utc)
        for lien, jour, source in (
            ("https://s/1", _auj.date().isoformat(), _nom_recent),
            ("https://s/2", (_auj - timedelta(days=20)).date().isoformat(), _nom_muet),
            ("https://s/3", (_auj - timedelta(days=20)).date().isoformat(), "Source Disparue"),
        ):
            _conn.execute(
                "INSERT INTO articles (lien, vu_le, source, categorie, titre) VALUES (?,?,?,?,?)",
                (lien, jour, source, "News", "t"))
        _conn.commit()
        _muettes = v.silent_sources(_conn, _auj)
        assert (_nom_muet, 20) in _muettes, _muettes
        assert all(nom != _nom_recent for nom, _ in _muettes), _muettes
        assert all(nom != "Source Disparue" for nom, _ in _muettes), _muettes
        _html = v.render_html({}, [], None, [], [], max_articles=10, silent=_muettes)
        assert "Silent sources" in _html and _nom_muet in _html
    finally:
        _conn.close()
        v.DB_FILE = _ancienne_db
print("Silent sources: OK")


# --- Modules Metasploit : seule la nouveauté compte ---------------------------
# La source est une liste cumulative de plus de trois mille CVE : publier son contenu serait
# absurde, et un premier passage sans cache ne doit rien sortir.
with tempfile.TemporaryDirectory() as _dossier_ms:
    _ancien_cache_ms = v.METASPLOIT_CACHE_FILE
    v.METASPLOIT_CACHE_FILE = str(Path(_dossier_ms) / "metasploit.json")

    class _RepMs:
        text = "CVE-2026-1111\nCVE-2026-2222\n"

        def raise_for_status(self):
            pass

    class _SessMs:
        def get(self, url, timeout=None):
            return _RepMs()

    try:
        assert v.collect_metasploit_cves(_SessMs())[0] == []   # première base : rien
        assert v.collect_metasploit_cves(_SessMs())[0] == []   # rien de neuf
        _RepMs.text = "CVE-2026-1111\nCVE-2026-2222\nCVE-2026-3333\n"
        _arts_ms = v.collect_metasploit_cves(_SessMs())[0]
        assert len(_arts_ms) == 1, _arts_ms
        assert _arts_ms[0].cves == ("CVE-2026-3333",), _arts_ms[0].cves
        _RepMs.text = "CVE-2026-1111\n"                         # source tronquée
        v.collect_metasploit_cves(_SessMs())
        assert len(v._read_metasploit_cache()) == 3, v._read_metasploit_cache()
    finally:
        v.METASPLOIT_CACHE_FILE = _ancien_cache_ms
print("Metasploit diff: OK")


# --- Enrichissement par télémétrie OffSeq -------------------------------------
# Aucune ligne ajoutée : seule la ligne de détail d'un article déjà présent gagne le contexte.
class _RepMirage:
    text = ("cve,name,kev,attempts,sources,first_seen,last_seen\n"
            "CVE-2017-9841,PHPUnit eval-stdin RCE,true,67314,235,2026-11-14,2026-11-20\n")

    def raise_for_status(self):
        pass


class _SessMirage:
    def get(self, url, timeout=None):
        return _RepMirage()


_mirage = v.fetch_mirage_stats(_SessMirage())
assert _mirage.get("CVE-2017-9841") == (67314, 235), _mirage
_now_mirage = datetime.now(timezone.utc)
_art_m = v.Article(source="S", title="CVE-2017-9841: PHPUnit", link="https://m/1",
                   date=_now_mirage, category=v.ALERTS, detail="eval-stdin RCE",
                   cves=("CVE-2017-9841",))
_art_n = v.Article(source="S", title="Autre sujet", link="https://m/2",
                   date=_now_mirage, category=v.NEWS)
_groupes_m = {"S": [_art_m, _art_n]}
assert v.enrich_with_mirage(_groupes_m, _mirage) == 1
assert "67,314 attempts" in _art_m.detail and "235 sources" in _art_m.detail, _art_m.detail
assert not _art_n.detail
assert v.enrich_with_mirage(_groupes_m, {}) == 0
print("Mirage enrichment: OK")


# --- État des sources : mémoire des pannes ------------------------------------
# Le statut se déduit des échecs consécutifs, il n'est jamais stocké : une source qui repart
# doit repasser en « active » d'elle-même.
with tempfile.TemporaryDirectory() as _d_src:
    _ancienne_db_src = v.DB_FILE
    v.DB_FILE = str(Path(_d_src) / "sources.db")
    _conn_src = v.open_db()
    try:
        _now_src = datetime.now(timezone.utc)
        v.record_source_results(_conn_src, {"Saine": (True, None, 4)})
        for _ in range(3):
            v.record_source_results(_conn_src, {"Morte": (False, "404 Client Error", 0)})
        v.record_source_results(_conn_src, {"Deplacee": (False, "301 Moved Permanently", 0)})
        v.record_source_results(_conn_src, {"Bloquee": (False, "403 Client Error", 0)})
        _etats_src = {e["nom"]: e for e in v.source_statuses(_conn_src, _now_src)}
        assert _etats_src["Saine"]["statut"] == "active", _etats_src["Saine"]
        assert _etats_src["Morte"]["statut"] == "dead", _etats_src["Morte"]
        assert _etats_src["Deplacee"]["statut"] == "moved", _etats_src["Deplacee"]
        assert _etats_src["Bloquee"]["statut"] == "blocked", _etats_src["Bloquee"]
        v.record_source_results(_conn_src, {"Morte": (True, None, 1)})
        _apres = {e["nom"]: e for e in v.source_statuses(_conn_src, _now_src)}
        assert _apres["Morte"]["statut"] == "active", _apres["Morte"]
        assert _apres["Morte"]["echecs"] == 0, _apres["Morte"]
    finally:
        _conn_src.close()
        v.DB_FILE = _ancienne_db_src
print("Source state: OK")


# --- Détection des flux déplacés ----------------------------------------------
# requests suit les redirections sans rien dire : un flux qui déménage répond normalement
# depuis sa nouvelle adresse, et personne ne s'en aperçoit.
class _RepRedir:
    def __init__(self, url):
        self.url = url


_src_redir = {"name": "T", "url": "https://blog.exemple.fr/feed/"}
assert v._redirect_target(_src_redir, _RepRedir("https://blog.exemple.fr/feed/")) is None
assert v._redirect_target(_src_redir, _RepRedir("https://blog.exemple.fr/feed")) is None       # barre oblique
assert v._redirect_target(_src_redir, _RepRedir("https://www.blog.exemple.fr/feed/")) is None  # www
_cible_redir = v._redirect_target(_src_redir, _RepRedir("https://www.exemple.com/rss.xml"))
assert _cible_redir == "https://www.exemple.com/rss.xml", _cible_redir
assert v._redirect_target(_src_redir, _RepRedir("https://blog.exemple.fr/rss.xml")) is not None
assert v.source_label({"nom": "X", "statut": "moved", "echecs": 0,
                       "erreur": "moved to https://n/1"}) == "X → https://n/1"
print("Redirect detection: OK")


# --- Recherche de l'adresse d'un flux mort ------------------------------------
# Une source « dead » a peut-être seulement changé de chemin : la page d'accueil déclare
# souvent son flux, et un candidat n'est retenu que s'il rend vraiment des entrées.
_FLUX_MIN = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
             b'<item><title>a</title></item><item><title>b</title></item>'
             b'<item><title>c</title></item></channel></rss>')


class _RepDecouv:
    def __init__(self, url, text="", content=b"", ok=True):
        self.url = url
        self.text = text
        self.content = content
        self.ok = ok

    def raise_for_status(self):
        if not self.ok:
            raise v.requests.RequestException("404")


class _SessDecouv:
    def __init__(self, avec_flux=True):
        self.avec_flux = avec_flux

    def get(self, url, timeout=None, headers=None):
        if url.rstrip("/") == "https://exemple.fr":
            return _RepDecouv(url, text='<link rel="alternate" type="application/rss+xml" '
                                        'href="/nouveau/feed.xml">')
        if self.avec_flux and url == "https://exemple.fr/nouveau/feed.xml":
            return _RepDecouv(url, content=_FLUX_MIN)
        return _RepDecouv(url, ok=False)


class _FluxFactice:
    def __init__(self, n):
        self.entries = [object()] * n


_parse_decouv = v.feedparser.parse
v.feedparser.parse = lambda contenu: _FluxFactice(3)
try:
    assert v.discover_feed(_SessDecouv(), "https://exemple.fr/vieux.xml") == \
        "https://exemple.fr/nouveau/feed.xml"
finally:
    v.feedparser.parse = _parse_decouv
# Sans flux valide derrière le candidat, on ne retient rien.
assert v.discover_feed(_SessDecouv(avec_flux=False), "https://exemple.fr/vieux.xml") is None
print("Feed discovery: OK")


# --- Lien de recherche pour une source introuvable ----------------------------
# Le suffixe entre parentheses est retire : « Mandiant (GTIG) » ne renvoie presque rien.
_lien_rech = v.feed_search_url("Mandiant (GTIG)")
assert "%22Mandiant%22" in _lien_rech, _lien_rech
assert "GTIG" not in _lien_rech, _lien_rech
_art_rech = v.Article(source="S", title="t", link="https://n/rech",
                      date=datetime.now(timezone.utc), category=v.NEWS)
_etats_rech = [
    {"nom": "Perdue", "statut": "dead", "echecs": 4, "candidat": None},
    {"nom": "Trouvee", "statut": "dead", "echecs": 4, "candidat": "https://x/rss"},
]
_html_rech = v.render_html({"S": [_art_rech]}, [], None, [], [], source_states=_etats_rech)
assert _html_rech.count("search</a>") == 1, _html_rech.count("search</a>")
assert "https://x/rss" in _html_rech
print("Search link: OK")


# --- Un flux déplacé n'est pas un flux cassé ----------------------------------
# Il répond parfaitement, depuis une autre adresse : le ranger avec les pannes fait croire
# à dix incidents là où il n'y a que dix déménagements.
_casses_b = [{"nom": "Morte", "statut": "dead", "echecs": 4, "candidat": None}]
_deplaces_b = [{"nom": "Bougee", "statut": "moved", "echecs": 0,
                "erreur": "moved to https://x/rss"}]
_html_b = v.render_html({"S": [_art_rech]}, [], None, [], [],
                        source_states=_casses_b, moved_states=_deplaces_b)
assert "Moved feeds" in _html_b, _html_b[:200]
_bloc_casse = _html_b.split("Broken sources")[1].split("</p>")[0]
assert "Bougee" not in _bloc_casse, _bloc_casse
assert "https://x/rss" in _html_b

# Une source retirée du code ne doit pas rester dans la table.
with tempfile.TemporaryDirectory() as _d_purge:
    _ancienne_db_purge = v.DB_FILE
    v.DB_FILE = str(Path(_d_purge) / "purge.db")
    _conn_purge = v.open_db()
    try:
        _conn_purge.execute("INSERT INTO sources (nom) VALUES ('Source Disparue')")
        _conn_purge.commit()
        assert v.prune_orphan_sources(_conn_purge) == 1
        _noms_restants = {r[0] for r in _conn_purge.execute("SELECT nom FROM sources")}
        assert "Source Disparue" not in _noms_restants, _noms_restants
    finally:
        _conn_purge.close()
        v.DB_FILE = _ancienne_db_purge
print("Moved vs broken: OK")


# --- Produit visé, lu dans le CPE du NVD --------------------------------------
# Un titre Sploitus ne dit que « CVE-2023-25157 exploit » : le produit vient de la même
# reponse NVD que le CVSS, donc sans requete supplementaire.
_cpe_ofbiz = {"configurations": [{"nodes": [{"cpeMatch": [
    {"criteria": "cpe:2.3:a:apache:ofbiz:18.12.0:*:*:*:*:*:*:*"}]}]}]}
assert v.extract_product(_cpe_ofbiz) == "apache ofbiz", v.extract_product(_cpe_ofbiz)
assert v.extract_product({}) is None
assert v.extract_product({"configurations": [{"nodes": [{"cpeMatch": [
    {"criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"}]}]}]}) is None
_art_prod = v.Article(source="S", title="CVE-2023-25157 exploit", link="https://n/p",
                      date=datetime.now(timezone.utc), category=v.ALERTS, product="apache ofbiz")
assert "apache ofbiz" in v._metrics(_art_prod), v._metrics(_art_prod)
print("Product extraction: OK")


# --- Dates non conformes ------------------------------------------------------
# Group-IB publie « Wed, 18 Nov 2026 14:30:33 », sans fuseau horaire : feedparser rejette,
# et le bot ignorait 373 articles sans que rien ne le signale.
assert v._entry_date({}) is None
_date_sans_fuseau = v._entry_date({"published": "Wed, 18 Nov 2026 14:30:33"})
assert _date_sans_fuseau is not None and _date_sans_fuseau.day == 18, _date_sans_fuseau
assert _date_sans_fuseau.year == 2026 and _date_sans_fuseau.tzinfo is not None
assert v._entry_date({"published_parsed": (2026, 11, 18, 14, 30, 33, 0, 0, 0)}).day == 18
assert v._entry_date({"published": "n'importe quoi"}) is None
print("Non-standard dates: OK")


# --- Titre de repli pour les flux sans titre ----------------------------------
# Mastodon n'expose pas de <title> : sans repli, ses billets arrivent en « Untitled item ».
class _FluxSansTitre:
    bozo = False
    entries = [{"link": "https://masto/1",
                "summary": "<p>Un billet Mastodon lisible</p>",
                "published": "Sat, 21 Nov 2026 10:00:00"}]


class _RepMasto:
    content = b""
    url = "https://mastodon.social/tags/infosec.rss"

    def raise_for_status(self):
        pass


class _SessMasto:
    def get(self, *a, **k):
        return _RepMasto()


_parse_masto = v.feedparser.parse
v.feedparser.parse = lambda *a, **k: _FluxSansTitre()
try:
    _arts_masto, _ = v.collect_rss(
        _SessMasto(),
        {"name": "Mastodon (infosec)", "url": "https://mastodon.social/tags/infosec.rss",
         "category": v.BLOGS},
        datetime(2026, 11, 20, tzinfo=timezone.utc), set())
finally:
    v.feedparser.parse = _parse_masto
assert _arts_masto, "aucun article produit"
assert _arts_masto[0].title == "Un billet Mastodon lisible", _arts_masto[0].title
print("Fallback title: OK")


# --- Une source active pendant le run n'est pas « muette » ---------------------
with tempfile.TemporaryDirectory() as _d_sil:
    _ancienne_db_sil = v.DB_FILE
    v.DB_FILE = str(Path(_d_sil) / "sil.db")
    _conn_sil = v.open_db()
    try:
        _auj_sil = datetime.now(timezone.utc)
        _nom_sil = v.RSS_SOURCES[0]["name"]
        _conn_sil.execute(
            "INSERT INTO articles (lien, vu_le, source, categorie, titre) VALUES (?,?,?,?,?)",
            ("https://s/9", (_auj_sil - timedelta(days=30)).date().isoformat(),
             _nom_sil, "News", "t"))
        _conn_sil.commit()
        assert (_nom_sil, 30) in v.silent_sources(_conn_sil, _auj_sil), "devrait etre muette"
        assert v.silent_sources(_conn_sil, _auj_sil, exclure={_nom_sil}) == [], \
            "une source active ne doit plus etre muette"
    finally:
        _conn_sil.close()
        v.DB_FILE = _ancienne_db_sil
print("Silent exclusion: OK")


# --- Fonctions pures : negation, traduction, regroupement ----------------------
# _positive doit ignorer une occurrence niee : sinon « not exploited » suffirait a declencher.
assert v._positive(v.RE_EXPLOITED, "actively exploited in the wild") is True
assert v._positive(v.RE_EXPLOITED, "not exploited in the wild") is False
assert v._positive(v.RE_EXPLOITED, "isn't being exploited") is False
assert v._positive(v.RE_RANSOM, "ransomware attack reported") is True
assert v._positive(v.RE_RANSOM, "no ransomware involved") is False

# translate_german : les locutions partent, le nom de produit et l'anglais restent.
assert v.translate_german("[UPDATE] [kritisch] GitLab: Mehrere Schwachstellen") == \
    "[UPDATED] [critical] GitLab: Multiple vulnerabilities"
assert "Privilegieneskalation" not in v.translate_german(
    "[NEU] [hoch] X: Schwachstelle ermöglicht Privilegieneskalation")
assert v.translate_german("Microsoft Exchange Server: new critical patch") == \
    "Microsoft Exchange Server: new critical patch"

# group_articles : dedup par lien, repli par CVE, et le lien replie reste memorise.
_grp_now = datetime.now(timezone.utc)


def _mk(source, titre, lien, cves=()):
    return v.Article(source=source, title=titre, link=lien, date=_grp_now,
                     category=v.NEWS, cves=cves)


_groupes, _liens = v.group_articles([
    ([_mk("S1", "PHP2Shell exploited", "https://g/1", ("CVE-2026-1",))], None),
    ([_mk("S2", "PHP2Shell elsewhere", "https://g/2", ("CVE-2026-1",))], None),
    ([_mk("S3", "Duplicate link", "https://g/1")], None),
])
_gardes = [x for xs in _groupes.values() for x in xs]
assert [x.title for x in _gardes] == ["PHP2Shell exploited"], _gardes
assert set(_liens) == {"https://g/1", "https://g/2"}, _liens
print("Pure functions: OK")


# --- Marquage des nouveautes --------------------------------------------------
# Le rapport glissant repete un article deux jours : seuls les liens jamais vus portent le 🆕.
_neuf = v.Article(source="S", title="Nouvelle attaque", link="https://n/1",
                  date=_grp_now, category=v.NEWS)
_vieux = v.Article(source="S", title="Deja vue", link="https://n/2",
                   date=_grp_now, category=v.NEWS)
_html_new = v.render_html({"S": [_neuf, _vieux]}, [], None, [], [],
                          max_articles=10, fresh={"https://n/1"})
assert '🆕 <a href="https://n/1"' in _html_new, _html_new[:400]
assert '🆕 <a href="https://n/2"' not in _html_new
# Sans le parametre, aucun marqueur : le rendu reste utilisable seul.
assert "🆕" not in v.render_html({"S": [_neuf]}, [], None, [], [], max_articles=10)
_txt_new = v.render_text({"S": [_neuf, _vieux]}, [], None, [], [],
                         max_articles=10, fresh={"https://n/1"})
assert "🆕 Nouvelle attaque" in _txt_new
assert "🆕 Deja vue" not in _txt_new
print("Fresh marker: OK")


# --- Repli d'agent pour les flux qui refusent un faux navigateur --------------
# Schneier, NVISO et Hackmageddon repondent 403 ou coupent la connexion quand le client se
# declare navigateur sans en etre un : la seconde tentative doit porter l'agent honnete.
class _RepFlux:
    def __init__(self, ok):
        self.ok = ok

    def raise_for_status(self):
        if not self.ok:
            raise v.requests.RequestException("403")


class _SessFlux:
    def __init__(self):
        self.appels = []

    def get(self, url, timeout=None, headers=None):
        heads = headers or {}
        self.appels.append(heads)
        # Seule la requete portant un User-Agent explicite reussit.
        return _RepFlux("User-Agent" in heads)


_sess_flux = _SessFlux()
v.fetch_feed(_sess_flux, "https://exemple.invalid/flux")
assert len(_sess_flux.appels) == 2, _sess_flux.appels
assert "User-Agent" not in _sess_flux.appels[0], _sess_flux.appels
assert _sess_flux.appels[1].get("User-Agent") == v.FEED_READER_UA, _sess_flux.appels
print("Feed retry: OK")


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
            collect_hibp=lambda *a, **k: ([], None),
            collect_euvd=lambda *a, **k: ([], None),
            collect_nvd_vendors=lambda *a, **k: ([], None),
            collect_metasploit_cves=lambda *a, **k: ([], None),
            fetch_mirage_stats=lambda *a, **k: {},
            collect_source=lambda source, since, seen: ([], None),
            enrich=lambda session, groups, cache, *a, **k: {},
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
