"""Tests de non-régression sur le scoring, la fusion et le plafond d'e-mail."""
from datetime import datetime, timezone

import feedparser
import pytest

import veille as v

MAINTENANT = datetime.now(timezone.utc)


@pytest.mark.parametrize("texte", [
    "Google Project Zero changes its 90-day disclosure policy",
    "Vendors must patch within 30 days of disclosure",
    "Offer valid for 10 days",
])
def test_zeroday_pas_de_faux_positif(texte):
    assert not v._positif(v.RE_ZERODAY, texte)


@pytest.mark.parametrize("texte", [
    "A new zero-day affects Chrome",
    "Chrome 0-day exploited",
    "Des 0days découverts",
    "Une faille jour-zéro",
])
def test_zeroday_vrais_positifs(texte):
    assert v._positif(v.RE_ZERODAY, texte)


@pytest.mark.parametrize("texte, attendu", [
    ("Exploited in the wild since March", True),
    ("The bug is not exploited in the wild", False),
    ("The flaw is not only exploited in the wild but also used by botnets", True),
    ("Aucune exploitation active n'a été observée", False),
])
def test_negation_exploitation(texte, attendu):
    assert v._positif(v.RE_EXPLOITEE, texte) is attendu


def test_cve_tiret_typographique_normalise():
    assert v.extraire_cves("Voir CVE\u20112026\u20111234 et cve-2025-99999") == {
        "CVE-2026-1234", "CVE-2025-99999"}


def test_scoring_ignore_le_corps_complet():
    flux = feedparser.parse(
        '<rss version="2.0"><channel><item><title>Our 90-day policy</title>'
        "<link>https://ex.org/a</link><pubDate>Sat, 24 Oct 2026 08:00:00 GMT</pubDate>"
        "<description>Policy update.</description>"
        '<content:encoded xmlns:content="http://purl.org/rss/1.0/modules/content/">'
        "<![CDATA[Cites CVE-2019-0001 and ransomware, actively exploited]]>"
        "</content:encoded></item></channel></rss>")
    entree = flux.entries[0]
    score, pastille = v.calculer_criticite(v._texte_court(entree))
    assert (score, pastille) == (0, "")
    assert not v.extraire_cves(v._texte_court(entree))
    assert v.extraire_cves(v._texte_entree(entree))  # le filtre, lui, voit le texte complet


def test_seuils_pastille():
    assert v.pastille(v.SEUIL_CRITIQUE) == "🔴"
    assert v.pastille(v.SEUIL_IMPORTANT) == "🟠"
    assert v.pastille(v.SEUIL_IMPORTANT - 1) == ""


def test_fusion_kev_rss_garde_le_lien():
    kev = v.Article(v.SOURCE_KEV, "CVE-2026-1111 : Acme Router", "https://nvd/CVE-2026-1111",
                    MAINTENANT, score=13, criticite="🔴", cves=("CVE-2026-1111",))
    rss = v.Article("BleepingComputer", "Acme router flaw exploited", "https://bc/1",
                    MAINTENANT, categorie=v.ACTUS, cves=("CVE-2026-1111",), tags="⚡")
    groupes, nouveaux = v.regrouper([([kev], None), ([rss], None)])
    assert list(groupes) == [v.SOURCE_KEV]
    assert groupes[v.SOURCE_KEV][0].aussi == [("BleepingComputer", "https://bc/1")]
    assert "⚡" in groupes[v.SOURCE_KEV][0].tags
    assert "https://bc/1" in nouveaux  # livré via « Aussi couvert par »


def test_plafond_email_et_rendu():
    articles = [v.Article("Zataz", f"Article {i}", f"https://z/{i}", MAINTENANT,
                          categorie=v.BLOGS, score=i) for i in range(60)]
    groupes = {"Zataz": articles}
    assert sum(len(x) for x in v.limiter_pour_email(groupes, 20).values()) == 20
    assert "Article 0" in v.rendre_html(groupes, [], None, None, [], [], max_articles=60)
    assert "Article 0" in v.rendre_texte(groupes, [], None, None, [], [], max_articles=60)


# --- Mode alerte -------------------------------------------------------------

def _article(titre="CVE-2026-9999 : Acme Gateway", score=16, cves=("CVE-2026-9999",), lien=None, **kw):
    return v.Article(kw.pop("source", v.SOURCE_KEV), titre, lien or f"https://nvd/{cves[0] if cves else titre}",
                     MAINTENANT, score=score, criticite=v.pastille(score), cves=tuple(cves), **kw)


def test_choisir_alertes_seuil_et_ordre():
    sous_seuil = _article(score=v.SEUIL_ALERTE - 1, cves=("CVE-2026-1",))
    grave = _article(score=v.SEUIL_ALERTE + 3, cves=("CVE-2026-2",))
    limite = _article(score=v.SEUIL_ALERTE, cves=("CVE-2026-3",))
    choisis = v.choisir_alertes({"x": [sous_seuil, limite, grave]}, set())
    assert choisis == [grave, limite]


def test_deja_signale_par_lien_ou_par_cve():
    a = _article(cves=("CVE-2026-5", "CVE-2026-6"))
    assert not v.deja_signale(a, set())
    assert v.deja_signale(a, {a.lien})
    assert not v.deja_signale(a, {"cve:CVE-2026-5"})                 # une seule CVE connue : nouveau
    assert v.deja_signale(a, {"cve:CVE-2026-5", "cve:CVE-2026-6"})   # toutes connues : déjà signalé


def test_preselection_garde_les_candidats_proches_du_seuil():
    marge = v.bonus_enrichissement(1.0, 10.0)
    proche = _article(score=v.SEUIL_ALERTE - marge, cves=("CVE-2026-7",))
    loin = _article(score=v.SEUIL_ALERTE - marge - 1, cves=("CVE-2026-8",))
    assert v.preselectionner({"x": [proche, loin]}, set()) == {"x": [proche]}


def test_rendre_alerte_sujet_propre_et_liens():
    a = _article(titre="Faille\ncritique <b>Acme</b>", detail="Description <script>x</script>",
                 aussi=[("BleepingComputer", "https://bc/1")])
    sujet, html_mail, texte = v.rendre_alerte([a], restants=2)
    assert "\n" not in sujet and sujet.startswith("🚨 Alerte cyber : Faille critique")
    assert "<script>" not in html_mail and "&lt;b&gt;Acme" in html_mail
    assert 'href="https://bc/1"' in html_mail and "https://bc/1" in texte
    assert "2 autre(s) alerte(s)" in texte


def test_main_alerte_amorcage_puis_alerte_unique(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    envoyes = []
    monkeypatch.setattr(v, "verifier_config", lambda: ("a@x", "pw", "b@x"))
    monkeypatch.setattr(v, "envoyer_email", lambda cfg, sujet, h, t: envoyes.append(sujet))
    monkeypatch.setattr(v, "creer_session", lambda: None)
    monkeypatch.setattr(v, "ouvrir_db", lambda: None)
    monkeypatch.setattr(v, "enrichir", lambda session, groupes, cache: {})
    monkeypatch.setattr(v, "collecter_source", lambda source, depuis, deja: ([], None))
    etat = {"kev": [_article(score=17)]}
    monkeypatch.setattr(v, "collecter_cisa_kev", lambda session, deja: (etat["kev"], None))

    assert v.main_alerte() == 0 and envoyes == []          # 1er passage : amorçage, aucun e-mail
    assert (tmp_path / v.ALERTE_FILE).exists()

    etat["kev"] = [_article(titre="CVE-2026-4242 : Nouveau", cves=("CVE-2026-4242",), score=18)]
    assert v.main_alerte() == 0 and len(envoyes) == 1      # nouvelle faille majeure : 1 e-mail
    assert "CVE-2026-4242" in envoyes[0]

    assert v.main_alerte() == 0 and len(envoyes) == 1      # même faille : pas de doublon

    etat["kev"] = [_article(titre="CVE-2026-1 : Mineure", cves=("CVE-2026-1",), score=v.SEUIL_ALERTE - 1)]
    assert v.main_alerte() == 0 and len(envoyes) == 1      # sous le seuil : rien
