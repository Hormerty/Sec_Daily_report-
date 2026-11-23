"""Non-regression tests for veille.py.

Plain functions only: they run under pytest (`python -m pytest -q`) and can also
be called directly by a small runner, so no fixture is required.
"""
import os
from datetime import datetime, timezone

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
