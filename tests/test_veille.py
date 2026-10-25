"""Tests de non-régression pour veille.py.
Ces tests passent avec la version corrigée et, pour les tests marqués
skipif, sont ignorés si tu utilises encore l'ancienne version.
"""
from datetime import datetime, timezone
import pytest
import veille
def _article(source="X", titre="t", lien="https://example.com/1", tags="", cves=()):
    return veille.Article(
        source=source,
        titre=titre,
        lien=lien,
        date=datetime(2026, 10, 25, tzinfo=timezone.utc),
        tags=tags,
        cves=cves,
    )
def test_extraire_cves_normalise_les_tirets():
    assert veille.extraire_cves("CVE-2024-1234") == {"CVE-2024-1234"}
    assert veille.extraire_cves("CVE‑2024‑12345") == {"CVE-2024-12345"}
    assert veille.extraire_cves("CVE-2024-123") == set()
def test_filtre_de_pertinence():
    assert not veille.est_pertinent("administration système et dossier partagé")
    assert veille.est_pertinent("CVE-2024-1234 : faille critique dans Exchange")
def test_rendu_html_echappe_les_titres():
    article = _article(titre="<script>alert(1)</script>", lien="https://example.com/?a=1&b=2")
    html = veille.rendre_html({"X": [article]}, [])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;b=2" in html
def test_compter_total():
    assert veille.compter({"X": [_article()]})["total"] == 1
@pytest.mark.skipif(not hasattr(veille, "_env_int"), reason="version non corrigée")
def test_env_int_tolere_une_valeur_invalide(monkeypatch):
    monkeypatch.setenv("_TEST_ENV_INT", "12h")
    assert veille._env_int("_TEST_ENV_INT", 36) == 36
@pytest.mark.skipif(not hasattr(veille, "_positif"), reason="version non corrigée")
def test_negation_exploitation():
    score, _ = veille.calculer_criticite("CVE-2024-1234 is not exploited in the wild")
    assert score == 3
@pytest.mark.skipif(not hasattr(veille, "limiter_pour_email"), reason="version non corrigée")
def test_limite_email():
    groupes = {f"S{i}": [_article() for _ in range(5)] for i in range(4)}
    limites = veille.limiter_pour_email(groupes, 8)
    assert sum(len(v) for v in limites.values()) == 8
