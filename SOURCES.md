# National CERT sources

Which national CERT each country is covered by, and why some are missing.

The rule is simple: a source is collected only if it publishes **advisory-grade content** as
a feed — products, CVE identifiers, fixes. Press releases, event announcements and awareness
campaigns are not collected, however official they are: in a daily brief they read as noise
next to the vulnerability of the day.

Verified on 2026-11-25 by requesting each URL, checking the content type, and parsing the
body as RSS or Atom. A feed that answers but yields no entries is treated as dead.

## Collected advisory feeds

| Country | Authority | Feed | Title language |
|---|---|---|---|
| AT | CERT.at | `https://cert.at/cert-at.de.warnings.rss_2.0.xml` | German |
| BE | CCB | `https://ccb.belgium.be/advisories.xml` | English |
| BE | Safeonweb | `https://safeonweb.be/fr/rss.xml` | French |
| DE | BSI CERT-Bund | `https://wid.cert-bund.de/content/public/securityAdvisory/rss` | German |
| EU | CERT-EU | `https://cert.europa.eu/publications/security-advisories-rss` | English |
| FI | NCSC-FI | `https://www.kyberturvallisuuskeskus.fi/feed/rss/en` | English |
| FR | CERT-FR | `https://cert.cyber.gouv.fr/feed/` | French |
| GB | NCSC UK | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` | English |
| HR | CERT.hr | `https://www.cert.hr/feed/` | Croatian |
| HU | NKI | `https://nki.gov.hu/figyelmeztetesek/riasztas/feed/` | Hungarian |
| IT | CSIRT Italia (ACN) | `https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192` | Italian |
| LU | CIRCL | `https://www.circl.lu/rss.xml` | English |
| NL | NCSC-NL | `https://advisories.ncsc.nl/rss/advisories` | Dutch |
| NO | NSM | `https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/` | Norwegian |
| PL | CERT Polska | `https://cert.pl/rss.xml` | Polish |
| SE | CERT-SE | `https://www.cert.se/feed` | Swedish |
| SI | SI-CERT | `https://www.cert.si/feed/` | Slovenian |

Non-English titles are translated by the phrase tables in `_TRADUCTIONS`, applied per source
through the `translate` key. Those tables were written from real titles pulled from each feed,
never from guessed vocabulary, because a wrong substitution would corrupt a product name.

Hungarian does not fit that model: the product sits in the middle of the sentence
("Riasztás az NGINX kritikus sérülékenységeiről"), so no word substitution can reorder it.
Hungarian titles are therefore rewritten through the `_MOTIFS` patterns, which capture the
product and place it into an English template. Because NKI also publishes awareness campaigns
and phishing notices, the source declares `require: "sérülékenység"`: an item is kept only if
its title mentions a vulnerability. On the feed as measured, that keeps seventeen of twenty
entries and translates all seventeen.

CERT-FR publishes one combined feed (`/feed/`) whose content is identical to the advisories
feed (`/avis/feed/`). Only the combined one is declared: keeping both fetched the same forty
items twice per run. Of the two separate alert feeds, `/alert/feed/` returns zero entries and
`/alerte/feed/` has not been updated since 2024.

## Verified, integration pending

| Country | Authority | Feed | Notes |
|---|---|---|---|
| ES | INCIBE-CERT | `https://www.incibe.es/en/incibe-cert/alerta-temprana/avisos/feed` | Spanish titles, but the feed carries an **English title** inside the description (`field--name-title`); extract it rather than translating |

## Deliberately excluded

| Country | Authority | Why |
|---|---|---|
| CH | BACS (ex-NCSC) | No feed of its own. The federal news service has one, but it carries press releases — conferences, laws, awareness campaigns |
| NL | NCSC nieuws | Covers the same vulnerabilities as the advisories feed, in Dutch and without severity. Collecting both would duplicate every Dutch advisory |
| CZ | NÚKIB | News feed only |
| DK | CFCS | News feed only |
| EE | CERT-EE | News feed only |
| LV | CERT.LV | News feed only |
| ES | CCN-CERT | Answers 403 to non-browser clients; INCIBE covers Spain |

## No usable feed found

| Country | Authority | Status |
|---|---|---|
| GR | EAA / cyber.gov.gr | No public RSS; news page only |
| HU | NKI | Covered — see the collected table |
| IE | NCSC Ireland | No public RSS; news page only |
| LT | NKSC | No public RSS; news page only |
| PT | CNCS | Unreachable from the test network |
| RO | DNSC | Unreachable from the test network |
| SK | SK-CERT | Feed link present but malformed |

Third-party bridges (RSS.app and similar) are not an option: they make the watch depend on an
unidentified service that can disappear, change its output, or relay altered content.

## Checking a candidate

```bash
curl -sI https://example.cert/feed/          # 200 and an XML content type?
curl -s  https://example.cert/feed/ | head   # <rss> or <feed>, with <item> or <entry>?
```

A feed that answers `200 text/html` is a web page, not a feed. A feed declared on a site is
usually visible in its source as `<link rel="alternate" type="application/rss+xml">`, even
when no RSS icon is displayed.
