"""Tests de NourSECBot : `pytest -q` à la racine du dépôt.

Les regex portent toute la logique de score : ces tests évitent les régressions silencieuses
(comme la virgule oubliée qui rendait « voo » indétectable).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

import veille

AUJOURDHUI = "2026-10-24"


# --- Extraction et score -------------------------------------------------------
def test_extraire_cves_normalise_tirets_typographiques_et_doublons():
    texte = "CVE\u20112026\u20111234 puis cve-2026-1234 et CVE-2025-99999"
    assert veille.extraire_cves(texte) == {"CVE-2026-1234", "CVE-2025-99999"}


def test_extraire_cves_ignore_les_ids_trop_courts():
    assert veille.extraire_cves("CVE-2026-12") == set()


def test_score_zero_day_exploite_avec_cve_est_critique():
    score, pastille = veille.calculer_criticite(
        "Zero-day CVE-2026-1111 in Fortinet VPN actively exploited in the wild")
    assert score >= veille.SEUIL_CRITIQUE
    assert pastille == "🔴"


def test_score_article_banal_sans_pastille():
    score, pastille = veille.calculer_criticite("Un nouveau guide pour configurer son routeur")
    assert score < veille.SEUIL_IMPORTANT
    assert pastille == ""


# --- Mots-clés ---------------------------------------------------------------
def test_voo_et_ores_sont_detectes_regression_virgule():
    assert veille.RE_CIBLES.search("Panne chez VOO ce matin")
    assert veille.RE_CIBLES.search("ORES annonce un correctif")
    assert not veille.RE_CIBLES.search("securitasvoo")  # l'ancienne concaténation accidentelle


def test_ransomware_nest_plus_un_mot_cle_cible():
    assert not veille.RE_CIBLES.search("ransomware attack on a hospital")
    # ... mais il reste pondéré par RE_RANSOM
    score, _ = veille.calculer_criticite("ransomware attack on a hospital")
    assert score == 3


def test_mots_entiers_pas_de_faux_positifs():
    assert not veille.RE_CIBLES.search("la dissapation des ibmx")  # "sap"/"ibm" ne sont pas des mots entiers
    assert veille.RE_CIBLES.search("Critical flaw in SAP NetWeaver")


@pytest.mark.parametrize("texte", [
    "Mass exploitation of a Citrix flaw",
    "Mirai variant spreads through routers",
    "Botnet takes advantage of unpatched cameras",
    "Researchers observe scanning activity targeting VPN",
    "Une campagne active cible les serveurs Exchange",
    "Ongoing campaign hits Ivanti appliances",
    "Widespread exploitation of the new bug",
])
def test_campagne_detectee(texte):
    assert veille.RE_CAMPAGNE.search(texte)
    assert "⚡" in veille.analyser_tags(texte)


@pytest.mark.parametrize("texte", [
    "Our awareness campaign for employees",
    "A phishing campaign targets bank customers",   # volontairement ignoré : trop fréquent
    "Widespread adoption of passkeys",
])
def test_campagne_non_detectee(texte):
    assert not veille.RE_CAMPAGNE.search(texte)


def test_campagne_augmente_le_score():
    base, _ = veille.calculer_criticite("Exchange flaw discussed")
    avec, _ = veille.calculer_criticite("Exchange flaw discussed amid mass exploitation")
    assert avec == base + 3


def test_filtre_de_pertinence():
    assert veille.est_pertinent("Une faille critique dans un routeur")
    assert veille.est_pertinent("New RCE in popular library")
    assert not veille.est_pertinent("Les meilleures recettes de crêpes")
    # mots entiers uniquement : "nist" dans "administration" et "dos" dans "dossier" ne comptent pas
    assert not veille.est_pertinent("Le dossier de l'administration communale")


# --- Top fournisseurs --------------------------------------------------------
def _kev(vendor: str, jours_avant: int, cve: str = "CVE-2026-0001", ransom: bool = False) -> dict:
    jour = (datetime.fromisoformat(AUJOURDHUI) - timedelta(days=jours_avant)).date().isoformat()
    return {"cveID": cve, "vendorProject": vendor, "dateAdded": jour,
            "knownRansomwareCampaignUse": "Known" if ransom else "Unknown"}


def test_top_fournisseurs_classement_et_fleches():
    vulns = (
        [_kev("Microsoft", 3)] * 5 + [_kev("Fortinet", 4)] * 3 + [_kev("Cisco", 5)] * 2
        + [_kev("Ivanti", 6)]                                   # nouveau ce mois-ci
        # période précédente (31 à 60 jours) : Fortinet 1er, Cisco 2e, Microsoft 3e
        + [_kev("Fortinet", 40)] * 4 + [_kev("Cisco", 41)] * 3 + [_kev("Microsoft", 42)] * 2
        + [_kev("Vieux", 200)] * 9                              # hors des deux périodes
    )
    top = veille.top_fournisseurs(vulns, AUJOURDHUI)
    assert [f["fournisseur"] for f in top] == ["Microsoft", "Fortinet", "Cisco", "Ivanti"]
    par_nom = {f["fournisseur"]: f for f in top}
    assert par_nom["Microsoft"]["n"] == 5 and par_nom["Microsoft"]["fleche"] == "▲"   # 3e -> 1er
    assert par_nom["Fortinet"]["fleche"] == "▼"                                        # 1er -> 2e
    assert par_nom["Cisco"]["fleche"] == "▼"                                           # 2e -> 3e
    assert par_nom["Ivanti"]["fleche"] == "🆕"
    assert par_nom["Fortinet"]["precedent"] == 4


def test_top_fournisseurs_regroupe_sans_tenir_compte_de_la_casse():
    vulns = [_kev("VMware", 2), _kev("vmware", 3), _kev("VMWARE ", 4)]
    top = veille.top_fournisseurs(vulns, AUJOURDHUI)
    assert len(top) == 1 and top[0]["n"] == 3


def test_top_fournisseurs_limite_n_et_ignore_dates_invalides():
    vulns = [_kev(f"V{i}", 1) for i in range(15)] + [{"vendorProject": "Sans date"}]
    assert len(veille.top_fournisseurs(vulns, AUJOURDHUI, n=10)) == 10
    assert all(f["fournisseur"] != "Sans date" for f in veille.top_fournisseurs(vulns, AUJOURDHUI, n=20))


def test_top_fournisseurs_liste_vide():
    assert veille.top_fournisseurs([], AUJOURDHUI) == []


# --- Base SQLite : migration, KEV, rappels --------------------------------------
@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(veille, "DB_FILE", str(tmp_path / "stats.db"))
    c = veille.ouvrir_db()
    assert c is not None
    yield c
    c.close()


def _inserer(conn, cve, vue_le, kev=1, ransomware=0):
    conn.execute("INSERT INTO cves (cve, vue_le, kev, ransomware) VALUES (?,?,?,?)",
                 (cve, vue_le, kev, ransomware))
    conn.commit()


def test_migration_ajoute_la_colonne_ransomware(tmp_path, monkeypatch):
    chemin = str(tmp_path / "ancienne.db")
    ancien = sqlite3.connect(chemin)
    ancien.executescript(
        "CREATE TABLE cves (cve TEXT PRIMARY KEY, vue_le TEXT NOT NULL, epss REAL, cvss REAL, "
        "kev INTEGER DEFAULT 0);"
        "INSERT INTO cves (cve, vue_le, kev) VALUES ('CVE-2026-0001', '2026-10-01', 1);")
    ancien.commit()
    ancien.close()
    monkeypatch.setattr(veille, "DB_FILE", chemin)
    c = veille.ouvrir_db()
    colonnes = {r[1] for r in c.execute("PRAGMA table_info(cves)")}
    assert "ransomware" in colonnes
    assert c.execute("SELECT ransomware FROM cves").fetchone()[0] == 0   # données conservées
    c.close()
    veille.ouvrir_db().close()  # deuxième ouverture : migration idempotente


def test_synchroniser_kev_marque_les_cve_deja_connues(conn):
    _inserer(conn, "CVE-2026-0001", "2026-10-20", kev=0)
    _inserer(conn, "CVE-2026-0002", "2026-10-20", kev=0)
    veille.synchroniser_kev(conn, [
        _kev("X", 1, "CVE-2026-0001", ransom=True),
        _kev("Y", 1, "CVE-2026-9999"),   # inconnue de la base : ignorée, pas d'erreur
    ])
    lignes = dict((c, (k, r)) for c, k, r in conn.execute("SELECT cve, kev, ransomware FROM cves"))
    assert lignes["CVE-2026-0001"] == (1, 1)
    assert lignes["CVE-2026-0002"] == (0, 0)


def test_rappels_filtrent_par_epss_ransomware_anciennete(conn, monkeypatch):
    _inserer(conn, "CVE-2026-0001", "2026-10-20")                 # 4 jours, EPSS élevé : gardée
    _inserer(conn, "CVE-2026-0002", "2026-10-20")                 # EPSS faible : écartée
    _inserer(conn, "CVE-2026-0003", "2026-10-21", ransomware=1)   # ransomware, EPSS faible : gardée
    _inserer(conn, "CVE-2026-0004", "2026-09-01")                 # trop ancienne : écartée
    _inserer(conn, "CVE-2026-0005", "2026-10-22", kev=0)          # hors KEV : écartée
    _inserer(conn, "CVE-2026-0006", "2026-10-22")                 # déjà affichée aujourd'hui : écartée
    _inserer(conn, "CVE-2026-0007", AUJOURDHUI)                   # vue aujourd'hui : pas un rappel

    demandees: list[str] = []

    def faux_epss(session, cves):
        demandees.extend(cves)
        return {"CVE-2026-0001": 0.92, "CVE-2026-0002": 0.02, "CVE-2026-0003": 0.01}

    monkeypatch.setattr(veille, "recuperer_epss", faux_epss)
    rappels = veille.rappels_kev(conn, None, AUJOURDHUI, deja_affichees={"CVE-2026-0006"})

    assert [r["cve"] for r in rappels] == ["CVE-2026-0003", "CVE-2026-0001"]   # ransomware d'abord
    assert rappels[1]["jours"] == 4 and rappels[1]["epss"] == pytest.approx(0.92)
    assert rappels[0]["ransomware"] is True
    assert "CVE-2026-0006" not in demandees and "CVE-2026-0005" not in demandees


def test_rappels_sans_api_epss_gardent_les_ransomwares(conn, monkeypatch):
    _inserer(conn, "CVE-2026-0001", "2026-10-20")
    _inserer(conn, "CVE-2026-0003", "2026-10-21", ransomware=1)
    monkeypatch.setattr(veille, "recuperer_epss", lambda s, c: {})   # panne de l'API EPSS
    rappels = veille.rappels_kev(conn, None, AUJOURDHUI, set())
    assert [r["cve"] for r in rappels] == ["CVE-2026-0003"]
    assert rappels[0]["epss"] is None


def test_rappels_limite_n(conn, monkeypatch):
    for i in range(10):
        _inserer(conn, f"CVE-2026-{1000 + i}", "2026-10-20")
    monkeypatch.setattr(veille, "recuperer_epss", lambda s, c: {x: 0.9 for x in c})
    assert len(veille.rappels_kev(conn, None, AUJOURDHUI, set(), n=3)) == 3


def test_rappels_sans_base_renvoient_liste_vide():
    assert veille.rappels_kev(None, None, AUJOURDHUI, set()) == []


def test_enregistrer_memorise_kev_et_ransomware_depuis_le_titre(conn):
    kev = veille.Article(
        source="CISA KEV", titre="CVE-2026-0010 : Acme Router", lien="https://nvd.nist.gov/vuln/detail/CVE-2026-0010",
        date=datetime.now(timezone.utc), tags="🔥",
        cves=("CVE-2026-0010", "CVE-2026-0011"))  # 0011 n'apparaît que dans la description
    veille.enregistrer(conn, {"CISA KEV": [kev]}, {"CVE-2026-0010": {}, "CVE-2026-0011": {}}, AUJOURDHUI)
    lignes = {c: (k, r) for c, k, r in conn.execute("SELECT cve, kev, ransomware FROM cves")}
    assert lignes["CVE-2026-0010"] == (1, 1)
    assert lignes["CVE-2026-0011"] == (0, 0)


# --- Collecte RSS : liens dangereux ------------------------------------------
class _Reponse:
    def __init__(self, contenu: bytes):
        self.content = contenu

    def raise_for_status(self):
        pass


class _Session:
    def __init__(self, contenu: bytes):
        self._contenu = contenu

    def get(self, url, timeout=None):
        return _Reponse(self._contenu)


def _flux(*liens: str) -> bytes:
    pub = format_datetime(datetime.now(timezone.utc))
    items = "".join(
        f"<item><title>Faille critique {i}</title><link>{lien}</link><pubDate>{pub}</pubDate></item>"
        for i, lien in enumerate(liens))
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{items}</channel></rss>'.encode()


def test_collecter_rss_refuse_les_liens_non_http():
    session = _Session(_flux("javascript:alert(1)", "data:text/html,x", "https://exemple.org/ok"))
    source = {"nom": "Test", "url": "https://exemple.org/feed", "categorie": veille.ALERTES}
    articles, erreur = veille.collecter_rss(
        session, source, datetime.now(timezone.utc) - timedelta(hours=2), set())
    assert erreur is None
    assert [a.lien for a in articles] == ["https://exemple.org/ok"]


# --- Rendu -------------------------------------------------------------------
def _article(**kw):
    base = dict(source="CISA KEV", titre="CVE-2026-0001 : Acme", lien="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
                date=datetime.now(timezone.utc), score=12, criticite="🔴", tags="⚡", cves=("CVE-2026-0001",))
    base.update(kw)
    return veille.Article(**base)


RAPPELS = [{"cve": "CVE-2026-0042", "jours": 4, "epss": 0.92, "ransomware": True}]
FOURNISSEURS = [{"fournisseur": "Micro<soft>", "n": 48, "precedent": 31, "fleche": "▲"}]


def test_rendu_html_contient_les_nouvelles_sections_et_echappe():
    groupes = {"CISA KEV": [_article()]}
    html_ = veille.rendre_html(groupes, [], None, None, RAPPELS, FOURNISSEURS)
    assert "Toujours d'actualité" in html_
    assert "vue depuis 4 j" in html_ and "EPSS 92 %" in html_ and "toujours dans la KEV" in html_
    assert "Failles exploitées par fournisseur" in html_
    assert "Micro&lt;soft&gt;" in html_ and "Micro<soft>" not in html_
    assert "⚡ Campagnes actives : 1" in html_


def test_rendu_texte_contient_les_nouvelles_sections():
    groupes = {"CISA KEV": [_article()]}
    texte = veille.rendre_texte(groupes, [], None, None, RAPPELS, FOURNISSEURS)
    assert "TOUJOURS D'ACTUALITÉ" in texte and "CVE-2026-0042" in texte
    assert "1. Micro<soft> (48) ▲" in texte


def test_rendu_sans_nouvelles_sections_reste_valide():
    groupes = {"CISA KEV": [_article()]}
    assert "Toujours d'actualité" not in veille.rendre_html(groupes, [])
    assert "FOURNISSEUR" not in veille.rendre_texte(groupes, [])


# --- Fusion par CVE : le signal ⚡ ne doit pas se perdre -------------------------
def test_regrouper_propage_la_campagne_a_larticle_conserve():
    kev = _article(tags="🔥", score=10, criticite="🔴")
    media = _article(source="BleepingComputer", titre="Mass exploitation of Acme flaw CVE-2026-0001",
                     lien="https://exemple.org/media", tags="⚡", score=8, criticite="🟠")
    groupes, nouveaux = veille.regrouper([([kev], None), ([media], None)])
    assert list(groupes) == ["CISA KEV"]                      # l'article média n'est pas affiché
    conserve = groupes["CISA KEV"][0]
    assert "⚡" in conserve.tags and "🔥" in conserve.tags
    assert conserve.score == 13
    assert conserve.aussi == ["BleepingComputer"]
    assert "https://exemple.org/media" in nouveaux           # mais son lien est mémorisé
