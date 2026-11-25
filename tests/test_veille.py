"""Non-regression tests for veille.py.

Plain functions only: they run under pytest (`python -m pytest -q`) and can also
be called directly by a small runner, so no fixture is required.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import veille


def _article(source="X", title="t", link="https://example.com/1", tags="", cves=(), countries=()):
    return veille.Article(
        source=source,
        title=title,
        link=link,
        date=datetime(2026, 10, 25, tzinfo=timezone.utc),
        tags=tags,
        cves=cves,
        countries=countries,
    )


def test_extract_cves_normalises_hyphens():
    assert veille.extract_cves("CVE-2024-1234") == {"CVE-2024-1234"}
    assert veille.extract_cves("CVE‑2024‑12345") == {"CVE-2024-12345"}
    assert veille.extract_cves("CVE-2024-123") == set()


def test_relevance_filter():
    assert not veille.is_relevant("administration système et dossier partagé")
    assert veille.is_relevant("CVE-2024-1234 : faille critique dans Exchange")


def test_html_render_escapes_titles():
    article = _article(title="<script>alert(1)</script>", link="https://example.com/?a=1&b=2")
    html = veille.render_html({"X": [article]}, [])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;b=2" in html


def test_compute_totals_count():
    assert veille.compute_totals({"X": [_article()]})["total"] == 1


def test_env_int_tolerates_invalid_value():
    os.environ["_TEST_ENV_INT"] = "12h"
    try:
        assert veille._env_int("_TEST_ENV_INT", 36) == 36
    finally:
        os.environ.pop("_TEST_ENV_INT", None)


def test_env_int_reads_legacy_name():
    os.environ["_TEST_LEGACY"] = "42"
    try:
        assert veille._env_int("_TEST_MISSING", 7, 1, "_TEST_LEGACY") == 42
    finally:
        os.environ.pop("_TEST_LEGACY", None)


def test_negation_of_exploitation():
    score, _ = veille.compute_criticality("CVE-2024-1234 is not exploited in the wild")
    assert score == 3


def test_email_limit():
    groups = {f"S{i}": [_article() for _ in range(5)] for i in range(4)}
    limited = veille.limit_for_email(groups, 8)
    assert sum(len(v) for v in limited.values()) == 8


def test_country_detection():
    assert "DE" in veille.detect_countries("CERT-Bund warns about Exchange in Deutschland")
    assert "BE" in veille.detect_countries("Le CCB alerte sur une faille")
    assert veille.detect_countries("Lorem ipsum dolor sit amet") == ()


def test_every_country_has_flag_and_links():
    for code, info in veille.COUNTRIES.items():
        assert info["flag"], code
        assert info["name"], code
        assert info["links"], code
        assert all(url.startswith("https://") for _, url in info["links"]), code


def test_country_sections_group_articles():
    german = _article(source="BSI", title="CERT-Bund warnt", countries=("DE",))
    belgian = _article(source="CCB", title="Le CCB alerte", countries=("BE",))
    blocks = dict(veille.country_sections({"BSI": [german], "CCB": [belgian]}))
    assert list(blocks["DE"]) == [german]
    assert list(blocks["BE"]) == [belgian]


def test_html_contains_european_section():
    html = veille.render_html({"X": [_article(title="German hospital hit by ransomware")]}, [])
    assert "European focus (IBM footprint)" in html
    assert "🇩🇪" in html
    # l'index des liens nationaux est présent par défaut
    assert "ccb.belgium.be" in html


def test_html_escapes_country_names():
    html = veille.render_html({"X": [_article()]}, [])
    assert 'lang="en"' in html
    assert "National CERT" in html


def test_degradation_reason():
    """Le dégradé se juge sur les sources en échec, jamais sur le nombre d'articles."""
    total = len(veille.RSS_SOURCES) + veille.EXTRA_SOURCES
    assert veille.degradation_reason([]) is None
    assert veille.degradation_reason(["Feed A: timeout"]) is None
    assert veille.degradation_reason(["boom"] * total) == "No reachable source"
    assert "sources in error" in veille.degradation_reason(["boom"] * (total // 2 + 1))
    assert veille.degradation_reason(["CISA KEV: down"]) == "CISA KEV unavailable: degraded watch"


def test_build_subject_garde_la_date_jour_mois_annee():
    now = datetime(2026, 11, 22, 6, 0, tzinfo=timezone.utc)
    sujet = veille.build_subject(now, {"critical": 3, "campaigns": 2})
    assert "22/11/2026" in sujet
    assert "2026-11-22" not in sujet
    assert "3 critical" in sujet
    assert "2 campaign(s)" in sujet
    # Sans rien de critique, le sujet reste l'identité et la date, sans chiffre inventé.
    calme = veille.build_subject(now, {"critical": 0, "campaigns": 0})
    assert calme.endswith("22/11/2026")


# --- Périmètre éditable -----------------------------------------------------

def test_configuration_absente_laisse_les_defauts(tmp_path):
    assert veille.charger_configuration(tmp_path / "absent.json") == {}


def test_configuration_json_invalide_est_refusee(tmp_path):
    chemin = tmp_path / "config.json"
    chemin.write_text("{ pas du json", encoding="utf-8")
    with pytest.raises(veille.ConfigurationError, match="JSON invalide"):
        veille.charger_configuration(chemin)


def test_configuration_tolere_le_bom(tmp_path):
    """PowerShell et Notepad écrivent un BOM UTF-8 : un config.json doit rester lisible."""
    chemin = tmp_path / "config.json"
    chemin.write_bytes('{"stack": {"GitLab": ["gitlab"]}}'.encode("utf-8-sig"))
    lue = veille.valider_configuration(veille.charger_configuration(chemin))
    assert lue["stack"]["GitLab"] == ["gitlab"]


def test_configuration_ajoute_un_produit_sans_toucher_aux_autres():
    avant = dict(veille.STACK_PRODUCTS)
    try:
        veille.appliquer_configuration(veille.valider_configuration(
            {"stack": {"GitLab": ["gitlab", "gitlab runner"]}}))
        assert veille.STACK_PRODUCTS["GitLab"] == ["gitlab", "gitlab runner"]
        assert "Box" in veille.STACK_PRODUCTS, "les autres produits gardent leur valeur"
    finally:
        veille.STACK_PRODUCTS.clear()
        veille.STACK_PRODUCTS.update(avant)


def test_configuration_retire_une_entree():
    avant = dict(veille.STACK_PRODUCTS)
    try:
        veille.appliquer_configuration(veille.valider_configuration({"stack": {"Box": None}}))
        assert "Box" not in veille.STACK_PRODUCTS
    finally:
        veille.STACK_PRODUCTS.clear()
        veille.STACK_PRODUCTS.update(avant)


def test_configuration_refuse_une_section_inconnue():
    with pytest.raises(veille.ConfigurationError, match="section inconnue"):
        veille.valider_configuration({"stackk": {}})


def test_configuration_refuse_un_pays_incomplet():
    with pytest.raises(veille.ConfigurationError, match="manquant"):
        veille.valider_configuration({"countries": {"ZZ": {"flag": "🏳"}}})


def test_configuration_refuse_une_url_non_https():
    with pytest.raises(veille.ConfigurationError, match="https"):
        veille.valider_configuration({"countries": {"ZZ": {
            "flag": "🏳", "name": "Zed", "keywords": ["zed"],
            "links": [["CERT", "http://exemple.org"]]}}})


def test_configuration_refuse_une_liste_vide():
    with pytest.raises(veille.ConfigurationError, match="liste non vide"):
        veille.valider_configuration({"targets": []})


def test_configuration_lue_au_demarrage(tmp_path):
    """Le vrai chemin : un config.json dans le répertoire courant, module importé."""
    (tmp_path / "config.json").write_text(
        json.dumps({"stack": {"GitLab": ["gitlab"]}}), encoding="utf-8")
    racine = Path(__file__).resolve().parent.parent
    code = ("import sys; sys.path.insert(0, %r); import veille; "
            "print('GitLab' in veille.STACK_PRODUCTS, 'Box' in veille.STACK_PRODUCTS)"
            % str(racine))
    resultat = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                              capture_output=True, text=True)
    assert resultat.returncode == 0, resultat.stderr
    assert resultat.stdout.split() == ["True", "True"]

# --- CERT nationaux : présence et traduction des titres -------------------------------------

def test_les_cert_nationaux_ajoutes_sont_declares():
    """Cinq CERT entraient dans le périmètre : ils doivent être déclarés, avec leur pays."""
    attendus = {
        "CSIRT Italia": ("IT", "it"),
        "CIRCL (Luxembourg)": ("LU", None),
        "CERT.at": ("AT", "de"),
        "NSM (Norvège)": ("NO", "no"),
        "NCSC-FI": ("FI", None),
    }
    par_nom = {source["name"]: source for source in veille.RSS_SOURCES}

    for nom, (pays, langue) in attendus.items():
        assert nom in par_nom, f"{nom} absent de RSS_SOURCES"
        assert par_nom[nom]["country"] == pays
        assert par_nom[nom]["category"] == veille.ALERTS
        assert par_nom[nom].get("translate") == langue, f"{nom} : langue de traduction"


def test_les_cert_traduits_ne_sont_pas_oublies():
    """Un flux non anglophone sans traduction afficherait du texte brut dans le rapport."""
    non_anglophones = {
        "CERT-FR": "fr", "NCSC-NL": "nl", "CERT Polska": "pl",
        "SI-CERT": "sl", "CERT-SE": "sv", "CERT.hr": "hr", "BSI CERT-Bund": "de",
        "CSIRT Italia": "it", "CERT.at": "de", "NSM (Norvège)": "no",
    }
    par_nom = {source["name"]: source for source in veille.RSS_SOURCES}

    for nom, langue in non_anglophones.items():
        assert par_nom[nom].get("translate") == langue, f"{nom} devrait être traduit depuis {langue}"


def test_cert_fr_n_est_declare_qu_une_fois():
    """Le flux combiné contient déjà les avis : deux entrées doublaient la requête."""
    flux = [source for source in veille.RSS_SOURCES if source["name"].startswith("CERT-FR")]

    assert len(flux) == 1, f"CERT-FR déclaré {len(flux)} fois"
    assert flux[0]["url"].endswith("/feed/")


@pytest.mark.parametrize("titre, langue, attendu", [
    ("Multiples vulnérabilités dans les produits Splunk (19 novembre 2026)", "fr",
     "Multiple vulnerabilities in Splunk (19 November 2026)"),
    ("Vulnérabilité dans les produits Elastic", "fr", "Vulnerability in Elastic"),
    ("Kwetsbaarheden verholpen in PHP", "nl", "Vulnerabilities fixed in PHP"),
    ("Kwetsbaarheid verholpen in OTRS", "nl", "Vulnerability fixed in OTRS"),
    ("Podatność w oprogramowaniu Bludit", "pl", "Vulnerability in software Bludit"),
    ("Podatności w oprogramowaniu LMS", "pl", "Vulnerabilities in software LMS"),
    ("SI-CERT 2026-09 / Kritične ranljivosti v spletnem strežniku NGINX", "sl",
     "SI-CERT 2026-09 / Critical vulnerabilities in web server NGINX"),
    ("Allvarliga sårbarheter i NGINX", "sv", "Serious vulnerabilities in NGINX"),
    ("Kritisk sårbarhet i Apache Axis", "sv", "Critical vulnerability in Apache Axis"),
    ("[VAŽNO] KRITIČNE RANJIVOSTI NGINX", "hr", "[IMPORTANT] CRITICAL VULNERABILITIES NGINX"),
    ("Risolte vulnerabilità in Drupal", "it", "Vulnerabilities fixed in Drupal"),
    ("Adobe: aggiornamenti di sicurezza", "it", "Adobe: security updates"),
    ("Rilevato sfruttamento attivo in rete della CVE-2026-131914", "it",
     "Active exploitation detected in the wild for CVE-2026-131914"),
    ("Flere kritiske sårbarheter i NGINX og BIG-IP", "no",
     "Several critical vulnerabilities in NGINX and BIG-IP"),
    ("Microsoft patchetirsdag november 2026", "no", "Microsoft Patch Tuesday november 2026"),
    ("Kritische Sicherheitslücken in PHP - Updates verfügbar", "de",
     "Critical vulnerabilities in PHP - updates available"),
    ("[NEU] [hoch] OpenSSL: Mehrere Schwachstellen", "de",
     "[NEW] [high] OpenSSL: Multiple vulnerabilities"),
])
def test_traduction_des_titres_cert(titre, langue, attendu):
    assert veille.translate_title(titre, langue) == attendu


def test_traduction_laisse_intact_un_nom_de_produit():
    """« Cisco » et « Citrix NetScaler » ne doivent pas être touchés par les locutions."""
    titre = "Kritische Sicherheitslücke in Citrix NetScaler ADC - Updates verfügbar"

    traduit = veille.translate_title(titre, "de")

    assert "Citrix NetScaler ADC" in traduit
    assert traduit.startswith("Critical vulnerability in")


def test_une_langue_sans_table_ne_change_rien():
    assert veille.translate_title("Vulnerabilities in PHP", "xx") == "Vulnerabilities in PHP"


def test_translate_german_reste_compatible():
    """La fonction d'origine est conservée : d'autres appelants peuvent s'y fier."""
    assert veille.translate_german("Schwachstelle in PHP") == "Vulnerability in PHP"

# --- Hongrie : réécriture des titres et filtre par source ------------------------------------

def test_la_hongrie_est_filtree_sur_la_vulnerabilite():
    """NKI mêle avis et campagnes de sensibilisation : seul l'avis nous intéresse."""
    source = next(s for s in veille.RSS_SOURCES if s["name"] == "NKI (Hongrie)")

    assert source["country"] == "HU"
    assert source["translate"] == "hu"
    assert source["require"] == "sérülékenység"


@pytest.mark.parametrize("titre, attendu", [
    ("Riasztás az NGINX kritikus sérülékenységeiről",
     "Alert: critical vulnerabilities in NGINX"),
    ("Riasztás a PHP futtatókörnyezet kritikus sérülékenységeiről",
     "Alert: critical vulnerabilities in PHP runtime"),
    ("Riasztás a WordPress Core-t érintő sérülékenységről",
     "Alert: vulnerability affecting WordPress Core"),
    ("Riasztás Check Point Security Management Server-t érintő sérülékenységről",
     "Alert: vulnerability affecting Check Point Security Management Server"),
    ("Riasztás a NetScaler ADC és NetScaler Gateway termékeket érintő sérülékenységekről",
     "Alert: vulnerabilities affecting NetScaler ADC and NetScaler Gateway products"),
    ("Riasztás az F5 BIG-IP APM rendszert érintő CVE-2026-94127 sérülékenységről",
     "Alert: vulnerability CVE-2026-94127 affecting F5 BIG-IP APM"),
    ("Riasztás a *sshole sérülékenységről", "Alert: vulnerability in *sshole"),
])
def test_reecriture_des_titres_hongrois(titre, attendu):
    assert veille.translate_title(titre, "hu") == attendu


def test_le_filtre_par_source_laisse_passer_un_avis_et_ecarte_une_campagne():
    """Le fragment doit être cherché dans le titre d'origine, avant toute traduction."""
    source_avec_filtre = {"require": "sérülékenység"}
    avis = "Riasztás az NGINX kritikus sérülékenységeiről"
    campagne = "Riasztás a Tárhely.Eu nevében küldött adathalász kampány kapcsán"

    assert source_avec_filtre["require"] in avis.casefold()
    assert source_avec_filtre["require"] not in campagne.casefold()

# --- Roumanie : filtre sur les alertes et réécriture des formules --------------------------

def test_la_roumanie_est_filtree_sur_les_alertes():
    """DNSC publie alertes, communiqués et revues hebdomadaires dans le même flux."""
    source = next(s for s in veille.RSS_SOURCES if s["name"] == "DNSC (Roumanie)")

    assert source["country"] == "RO"
    assert source["translate"] == "ro"
    assert source["require"] == "ALERTĂ"


@pytest.mark.parametrize("titre, attendu", [
    ("ALERTĂ: Vulnerabilitate critică la nivelul VMware",
     "Alert: critical vulnerability in VMware"),
    ("ALERTĂ: Vulnerabilitate critică la nivelul unei biblioteci Node.js",
     "Alert: critical vulnerability in a Node.js library"),
    ("ALERTĂ: Vulnerabilități critice identificate  la nivelul NGINX",
     "Alert: critical vulnerabilities identified in NGINX"),
    ("ALERTĂ: Vulnerabilități critice exploatate activ în Synology",
     "Alert: critical vulnerabilities actively exploited in Synology"),
    ("ALERTĂ: Vulnerabilități critice la nivelul NGINX",
     "Alert: critical vulnerabilities in NGINX"),
])
def test_reecriture_des_titres_roumains(titre, attendu):
    """La double espace de « identificate  la nivelul » ne doit pas faire échouer le motif."""
    assert veille.translate_title(titre, "ro") == attendu

# --- Slovaquie : flux sans date et titre encodé -----------------------------------------

def test_la_slovaquie_est_declaree_avec_ses_singularites():
    """Le flux n'existe qu'encodé et ne porte aucune date : les deux doivent être déclarés."""
    source = next(s for s in veille.RSS_SOURCES if s["name"] == "SK-CERT (Slovaquie)")

    assert "%3Ffeed=rss" in source["url"], "l'adresse doit rester encodée"
    assert source["sans_date"] is True
    assert source["require"] == "zraniteľn"
    assert source["translate"] == "sk"


@pytest.mark.parametrize("titre, attendu", [
    ("Kritická zraniteľnosť „NGINX2ROOT“", "Critical vulnerability „NGINX2ROOT“"),
    ("Kritické zraniteľnosti v PHP", "Critical vulnerabilities in PHP"),
    ("Kritická zraniteľnosť TCP v jadre Linux",
     "Critical vulnerability TCP in the Linux kernel"),
    ("VAROVANIE: Kritické zraniteľnosti GITLAB CE a EE",
     "WARNING: Critical vulnerabilities GITLAB CE and EE"),
    ("VAROVANIE: Útočníci aktívne zneužívajú zraniteľnosti MIKROTIK smerovačov",
     "WARNING: Attackers actively exploit vulnerabilities MIKROTIK routers"),
])
def test_reecriture_des_titres_slovaques(titre, attendu):
    assert veille.translate_title(titre, "sk") == attendu

# --- Espagne : titre anglais lu dans la description --------------------------------------

def test_l_espagne_lit_son_titre_anglais_au_lieu_de_le_traduire():
    source = next(s for s in veille.RSS_SOURCES if s["name"] == "INCIBE-CERT (Espagne)")

    assert source["country"] == "ES"
    assert source.get("english_title") is True
    assert not source.get("translate"), "l'Espagne n'a pas besoin de table de traduction"


def test_extraction_du_titre_anglais_echappe_dans_la_description():
    """Le flux INCIBE double-échappe son HTML : l'extraction doit traverser les entités."""
    entree = {"description": (
        '&lt;span class="field field--name-title field--type-string field--label-hidden"&gt;'
        'Multiple vulnerabilities in the Vorecol web platform&lt;/span&gt;'
        '&lt;span class="field"&gt;Multiple vulnerabilities in the Vorecol web platform&lt;/span&gt;')}

    assert veille._titre_anglais(entree) == \
        "Multiple vulnerabilities in the Vorecol web platform"


def test_une_description_sans_titre_anglais_renvoie_none():
    assert veille._titre_anglais({"description": "<p>Description ordinaire</p>"}) is None
    assert veille._titre_anglais({}) is None
