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
| ES | INCIBE-CERT | `https://www.incibe.es/en/incibe-cert/alerta-temprana/avisos/feed` | Spanish titles, English title inside the description |
| EU | CERT-EU | `https://cert.europa.eu/publications/security-advisories-rss` | English |
| FI | NCSC-FI | `https://www.kyberturvallisuuskeskus.fi/feed/rss/en` | English |
| FR | CERT-FR | `https://cert.cyber.gouv.fr/feed/` | French |
| GB | NCSC UK | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` | English |
| HR | CERT.hr | `https://www.cert.hr/feed/` | Croatian |
| HU | NKI | `https://nki.gov.hu/feed/riasztasok/` | Hungarian |
| IE | NCSC Ireland | `https://www.ncsc.gov.ie/news/alerts.rss` | English |
| IT | CSIRT Italia (ACN) | `https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192` | Italian |
| LU | CIRCL | `https://www.circl.lu/rss.xml` | English |
| NL | NCSC-NL | `https://advisories.ncsc.nl/rss/advisories` | Dutch |
| NO | NSM | `https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/` | Norwegian |
| PL | CERT Polska | `https://cert.pl/rss.xml` | Polish |
| RO | DNSC | `https://dnsc.ro/feed` | Romanian |
| SE | CERT-SE | `https://www.cert.se/feed` | Swedish |
| SI | SI-CERT | `https://www.cert.si/feed/` | Slovenian |
| SK | SK-CERT | `https://www.sk-cert.sk/index.html%3Ffeed=rss` | Slovak |
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

The Romanian DNSC feed mixes vulnerability alerts with press releases and a weekly news
roundup; `require: "ALERTĂ"` keeps the five alerts of a ten-entry feed and drops the rest.
Titles are rewritten by patterns (« ALERTĂ: Vulnerabilitate critică la nivelul VMware » →
« Alert: critical vulnerability in VMware »), and whitespace is normalised first because the
feed sometimes writes a double space inside the formula.

Two peculiarities of the Slovak SK-CERT feed are worth recording, because both would have
silently emptied the source. Its address only works URL-encoded — `/index.html%3Ffeed=rss`,
with `%3F` in place of `?`; the plain form answers 404. And its entries carry **no date at
all**, which the collector treats as "skip"; the source therefore declares `sans_date: true`
and is dated on arrival. Deduplication by link prevents the same entries from being published
twice, and the feed holds only ten of them.

CERT-FR publishes one combined feed (`/feed/`) whose content is identical to the advisories
feed (`/avis/feed/`). Only the combined one is declared: keeping both fetched the same forty
items twice per run. Of the two separate alert feeds, `/alert/feed/` returns zero entries and
`/alerte/feed/` has not been updated since 2024.

## Vendors and distributions

The table above covers national authorities. Two distribution feeds were added in November
2026, because a server fleet is more often affected by its package manager than by a national
alert:

| Distributor | Endpoint | Format |
|---|---|---|
| Ubuntu | `https://ubuntu.com/security/notices/rss.xml` | RSS, USN identifiers |
| Red Hat | `https://access.redhat.com/hydra/rest/securitydata/cve.json` | JSON API, one record per CVE |

Ubuntu publishes an RSS feed and is declared like any other source. Red Hat publishes no feed:
the engine queries its security data API with `after=<yesterday>`, then filters again on the
exact publication timestamp, because `after` works at day granularity. The 27-hour window
measured held twenty-two CVEs, each with its severity and CVSS score.

Debian was checked as well and left out: its security tracker publishes no feed, and the bulk
JSON is 90 MB per fetch.

## Verified, integration pending

Nothing at present.

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
| LT | NKSC | No public RSS; news page only |
| PT | CNCS | A feed exists (`cncs.gov.pt/docs/noticias/feed-rss/index.xml`) but the publisher answers 513 to every non-browser client |

Two external registries were checked as part of this audit: the
[pulsedive/certrss](https://github.com/pulsedive/certrss) registry (37 CERTs) and the
[threatfilter.dev](https://threatfilter.dev/sources) directory (52 feeds). Neither lists
Greece, Ireland or Lithuania, which corroborates the findings above. The certrss registry is
also where the Portuguese feed came from; it was tested and refused.

One source is technically available but outside the current perimeter: **CERT-UA**
(`https://cert.gov.ua/api/articles/rss`). It answers correctly, publishes APT campaign
research rather than vulnerability advisories, updates a few times a year, and writes in
Ukrainian — the campaign names (UAC-0277, LUNEXSTEAL) are Latin, the rest is not.

Third-party bridges (RSS.app and similar) are not an option: they make the watch depend on an
unidentified service that can disappear, change its output, or relay altered content.

## External aggregators evaluated and refused

Two aggregators were examined in November 2026 because they promised to spare us work. Neither
was integrated, and the reasons are worth keeping.

**[EUVD](https://euvd.enisa.europa.eu) — ENISA's European Vulnerability Database** is a primary
source and its JSON API works: `/api/search?fromDate=…&toDate=…&size=100` returns a date
window, with CVSS 4.0 vectors, EPSS, vendor, product and the publishing CERT as `assigner`.
The 25th of November alone held **294 entries**, and a three-day window 1 170. That volume, and
the fact that an entry's `assigner` was CERT-PL — a feed collected directly, with its country
and its translation — made it a duplicate with a heavier payload rather than a new source. Its
`/api/lastvulnerabilities` endpoint, the only one meant for polling, returns four entries.

**[cve.now](https://github.com/sazabi/cve.now) — a hosted feed** merging the CVE List, GHSA,
OSV, NVD, EUVD, CISA KEV, EPSS and Exploit-DB into one entry per vulnerability, with RSS, a
JSON API and an MCP server, no account required. Its filters work (`?filter=critical`,
`?filter=kev`), each returning 200 entries. It was refused for one reason above all: its titles
and summaries are written by a model, not by the vendor or the CERT. A brief whose job is to
say whether a version is affected cannot quote a paraphrase — a summary may drop a version
range or invert a condition, and nothing in the entry shows where the phrasing came from. It
also repackages sources already queried first-hand, mixes breach news with advisories, and
re-publishes an entry whenever a proof of concept appears (the guid carries a timestamp, so the
same CVE returns).

What both do well is deduplicate per vulnerability and merge severity data. That is precisely
what the engine already does across its 123 feeds, with the country provenance kept.

A third lead came from [haxdoggy/vulnerability-databases](https://github.com/haxdoggy/vulnerability-databases),
a curated directory of vulnerability databases (a README table and a `databases.json`, CC-BY-4.0).
It is a catalogue, not a service: it offers neither an API nor downloadable collections, and its
Europe section lists exactly the CERTs already collected here — which is a useful confirmation
rather than a discovery. Its most interesting entry is **GCVE**, CIRCL's decentralised CVE
database: `https://db.gcve.eu/api/vulnerability/GCVE-1-2026-0001` answers with a CVE-5 style
JSON record. It is a lookup base, like EUVD, not a feed, and the same reasoning applies.

## Checking a candidate

```bash
curl -sI https://example.cert/feed/          # 200 and an XML content type?
curl -s  https://example.cert/feed/ | head   # <rss> or <feed>, with <item> or <entry>?
```

A feed that answers `200 text/html` is a web page, not a feed. A feed declared on a site is
usually visible in its source as `<link rel="alternate" type="application/rss+xml">`, even
when no RSS icon is displayed.
