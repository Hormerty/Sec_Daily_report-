# National CERT sources

Which national CERT each country is covered by, and why some are missing.

The rule is simple: a source is collected only if it publishes **advisory-grade content** as
a feed: products, CVE identifiers, fixes. Press releases, event announcements and awareness
campaigns are not collected, however official they are: in a daily brief they read as noise
next to the vulnerability of the day.

Verified on 2026-11-25 by requesting each URL, checking the content type, and parsing the
body as RSS or Atom. A feed that answers but yields no entries is treated as dead.

## Reference data, which is not a feed

Everything above is a *feed*: someone writes a headline, and we link to it. A second category is
consumed by the engine and was never described here, because the rule at the top of this page only
covers advisory feeds: the **reference datasets**. They have no headline, no author and no
publication rhythm; they are lookup tables, and they carry their own terms.

| Dataset | Used for | Terms |
|---|---|---|
| **CISA KEV** | exploited-in-the-wild flag, remediation deadline | US Government work, public domain |
| **NVD** | CVSS, product, vendor | US Government work, public domain |
| **GitHub Advisory Database** | advisories for open-source components | CC BY 4.0 |
| **CVE List V5** (`cvelistV5`) | CVE records the day they are published, with their `affected` products | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| **EPSS** (FIRST) | exploitation probability | to confirm before redistribution |
| **EUVD** (ENISA) | European vulnerability database | to confirm before redistribution |

The CVE Program Terms of Use are precise rather than vague: they grant a perpetual, worldwide,
royalty-free, irrevocable licence to reproduce, prepare derivative works of, and distribute the
CVE List, **provided every copy reproduces MITRE's copyright designation and the licence itself**.
That is permissive enough for this project, and it is the only one of the six that asks anything in
return.

Consequences for the code, when the CVE collector is written:

- the report footer carries `CVE® is a registered trademark of The MITRE Corporation. Records used
  under the CVE Program Terms of Use.`;
- the same notice appears in the README, so a copy of the report is never handed over without it;
- the two "to confirm" rows are checked before any of their data is redistributed, not merely read
  for ranking.

This section does not change the rule at the top of the page. It names the second category, so the
next person does not have to rediscover that a lookup table is not a feed.

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
silently emptied the source. Its address only works URL-encoded: `/index.html%3Ffeed=rss`,
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
| CH | BACS (ex-NCSC) | No feed of its own. The federal news service has one, but it carries press releases: conferences, laws, awareness campaigns |
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
Ukrainian: the campaign names (UAC-0277, LUNEXSTEAL) are Latin, the rest is not.

Third-party bridges (RSS.app and similar) are not an option: they make the watch depend on an
unidentified service that can disappear, change its output, or relay altered content.

[**RSS-Bridge**](https://github.com/RSS-Bridge/rss-bridge) is the honest version of that idea: it
is self-hosted, so nothing is relayed by a stranger. Its 553 bridges contain none for the three
countries still missing: the closest names are Comboios de Portugal and Cybernews, neither a
CERT. Using it would therefore mean writing a PHP bridge per site and keeping a web server
running beside a 15 MB desktop application, and it would not open Portugal at all: the page sits
behind a bot check, which a self-hosted scraper cannot pass either. The gap is the same work in
a heavier runtime, with the same fragility: a scraper that returns nothing looks like a quiet
day, where a dead feed appears in the error line.

## Removed after measurement, 27 November 2026

Each line was checked against seven days of its own feed, counting the items the relevance filter
would still keep. A source that publishes gadgets and discounts has no place in a watch, however
serious it is about technology.

| Source | Items / 7 days | Kept | Why it left |
|---|---|---|---|
| 01net | 30 | **0** | deals and gadgets: `-45 %`, tablets, scooters |
| Korben | 31 | 2 (6 %) | general technology blog |
| Clubic | 50 | 6 (12 %) | deals, robot vacuums, VPN offers |
| Next | 50 | 8 (16 %) | general technology news |
| HackerSploit | (|) | last published February 2023 |
| NetworkChuck | 0 |: | the feed returns nothing |

These produced the noise a reader notices first: *« Oui, on peut faire tourner macOS sur une base
Linux »*, *« Cet aspirateur robot est à -71 % »*. For comparison, the sources kept at the same
measurement: SecurityWeek and The Record 100 %, The Hacker News 85 %, Dark Reading 83 %.

### Re-checked on 28 November 2026

	ools/verifier_refus.py replays the measurement on every refused source: it reads the bold
entries of this page, requests each one, and prints what it answers today. The verdicts below come
from its output, not from memory.

| Source | State on 28 November | Refusal |
|---|---|---|
| vulneraibility.com | 34 entries, last one 16 October | holds, and the site now looks abandoned |
| cve.now | 170 stars, pushed 11 November, Apache-2.0 | holds: its titles are model-written, so untraceable |
| OSV | no feed, per-ecosystem archives | holds: a stack-audit API, not a daily source |
| cvelistV5 | 3 333 stars, pushed today, no licence, 3.4 GB | accepted as reference data, collector not written yet |
| trickest/cve | 8 260 stars, pushed yesterday, MIT, 894 MB | holds: 70 % of critical CVEs already carry KEV or SSVC |
| alex-ilgayev/secfeed | 32 stars, last push March 2025 | holds: abandoned, and used only as a candidate list |
| SharonBrizinov/secfeed | 27 stars, last push January 2025 | holds: same |
| EUVD | see above | **the page was wrong**: it is integrated |

## External aggregators evaluated and refused

**[vulneraibility.com](https://www.vulneraibility.com/blog/rss.xml): a misspelled domain, and a
trademark problem before it is a data problem.** The name is not a word: it is `vulnerability` with
an extra `i`, registered on 2025-11-08, while `vulnerability.com` has existed since 2000-01-19. The
feed answers correctly and looks like a security blog, but of its thirty entries none carries a CVE,
a product or a fix: they are guides, definitions and product pitches, several of which end with
"here is how vulneraibility.com produces it". It is a competitor's content marketing on a domain
built to catch visitors of another site, so it is refused as a source and noted here so that it is
not proposed again.

Two aggregators were examined in November 2026 because they promised to spare us work. Neither
was integrated, and the reasons are worth keeping.

**[EUVD](https://euvd.enisa.europa.eu): ENISA's European Vulnerability Database** is
**integrated**, and this page said the opposite until 28 November 2026. The error was found by
re-reading the code: `collect_euvd` runs in the daily report and in the alert pass, against
`/api/kev/dump`, the European equivalent of the CISA catalogue: 1 783 entries carrying `cveId`,
`euvdId`, `dateAdded` and the sources. What made it look refused is the volume of `/api/search`:
294 entries on 25 November alone, mostly CERT-PL advisories we already collect directly. The
collector therefore reads the KEV dump, keeps only recent additions, and drops any CVE the
American KEV already lists, so the same flaw is not printed twice.

**[cve.now](https://github.com/sazabi/cve.now): a hosted feed** merging the CVE List, GHSA,
OSV, NVD, EUVD, CISA KEV, EPSS and Exploit-DB into one entry per vulnerability, with RSS, a
JSON API and an MCP server, no account required. Its filters work (`?filter=critical`,
`?filter=kev`), each returning 200 entries. It was refused for one reason above all: its titles
and summaries are written by a model, not by the vendor or the CERT. A brief whose job is to
say whether a version is affected cannot quote a paraphrase: a summary may drop a version
range or invert a condition, and nothing in the entry shows where the phrasing came from. It
also repackages sources already queried first-hand, mixes breach news with advisories, and
re-publishes an entry whenever a proof of concept appears (the guid carries a timestamp, so the
same CVE returns).

**[OSV](https://osv.dev): Google's open source vulnerability database** has no feed: its
site announces only a blog RSS, and its data arrives as per-ecosystem archives (PyPI 36 MB,
npm 212 MB, Go 12 MB). It is an API for exact lookups, and a good one: querying
`django 4.2.0` returns 96 advisories, version-precise. That is a stack-audit capability,
not a source for a daily brief, and it would mean sending the user's dependency list to a
third party. Left out, but worth remembering if the stack ever accepts a lockfile.

What both do well is deduplicate per vulnerability and merge severity data. That is precisely
what the engine already does across its 123 feeds, with the country provenance kept.

**[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5): the official CVE List.**
3 324 stars, pushed every few minutes, and the registry every other source derives from. It
offers no daily feed: cves/delta.json covers the window since the mirror last refreshed (404
bytes on 26 November, one updated CVE), and cves/deltaLog.json holds the rolling log at 28,3 MB
for 3 786 entries. The clean interface is the CVE Services API
(cveawg.mitre.org/api/cve/CVE-…, 3,2 KB, no key). Kept out because the engine is
source-driven: an item enters the report because a publisher wrote it, never because a registry
numbered it. Its real use would be a fallback when NVD has not yet analysed a CVE we already
carry: the CNA description and affected versions are there before NVD's are.

**[trickest/cve](https://github.com/trickest/cve): a public proof-of-concept index.** MIT,
8 255 stars, refreshed daily: one markdown sheet per CVE (CVE-2026-102275.md, 1,4 KB) with
product, versions, CWE, description and the PoC links, at a path derived from the identifier:
the same shape as CISA Vulnrichment. Two bulk files sit at the root, github.txt (17,4 MB) and

eferences.txt (14,4 MB), as CVE-xxxx - url pairs. Refused for now: the SSVC decision we
already read answers the same question authoritatively, and Sploitus, Exploit-DB and the ZDI
feed already carry the PoCs; adopting this one would cost 17 MB a day, or one more request per
enriched CVE, for the number of proofs rather than their existence. The bulk files also hold
noise (dozens of CVE-0000-0000 lines). Worth remembering if SSVC coverage ever feels thin.
Its neighbour [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) does the same
job with JSON instead of markdown: 8 236 stars, CC0, one file per CVE holding the GitHub API
record of each proof-of-concept repository, refreshed daily. Easier to parse than markdown, and
still the same answer to the same question; the only extra it carries is how many repositories
exist and how popular they are, which does not change a remediation decision.

A third lead came from [haxdoggy/vulnerability-databases](https://github.com/haxdoggy/vulnerability-databases),
a curated directory of vulnerability databases (a README table and a `databases.json`, CC-BY-4.0).
It is a catalogue, not a service: it offers neither an API nor downloadable collections, and its
Europe section lists exactly the CERTs already collected here: which is a useful confirmation
rather than a discovery. Its most interesting entry is **GCVE**, CIRCL's decentralised CVE
database: `https://db.gcve.eu/api/vulnerability/GCVE-1-2026-0001` answers with a CVE-5 style
JSON record. It is a lookup base, like EUVD, not a feed, and the same reasoning applies.

**[alex-ilgayev/secfeed](https://github.com/alex-ilgayev/secfeed)** is a Go aggregator with an
AI summariser, last pushed in March 2025. Nothing in it is usable here, but its config.yml holds
25 feeds, so it was read as a candidate list: 13 are already collected, and of the 12 others,
whose state was checked on 26 November, eight are gone: Threatpost's last entry dates from August
2022, Rapid7's blog answers 404, Veracode's feed is empty, Sophos and Digital Shadows no longer
answer. A namesake, **[SharonBrizinov/secfeed](https://github.com/SharonBrizinov/secfeed)**, is a closer
cousin than the Go one: 346 lines of Python, MIT, SQLite state, a poll every two hours and
notifications to Slack, Telegram, Signal or Discord. Its method is the one refused here: HTML
scraped by regular expressions: and its sources are CISA and CERT-EU, already collected, plus
research blogs. Tested on 26 November: Claroty Team82 answers 410 Gone, SRC Incite and doar-e
publish no feed, Tenable's blog is alive. Nothing added, but one idea worth naming: chat delivery
as an alternative to mail, if alerts should ever reach a phone.

The four survivors are media or vendor research (SecurityAffairs, Ars Technica, ZDNet,
Check Point, Kaspersky, Tenable). None is an advisory source, and the brief already carries sixty
blogs: nothing added.

## Checking a candidate

```bash
curl -sI https://example.cert/feed/          # 200 and an XML content type?
curl -s  https://example.cert/feed/ | head   # <rss> or <feed>, with <item> or <entry>?
```

A feed that answers `200 text/html` is a web page, not a feed. A feed declared on a site is
usually visible in its source as `<link rel="alternate" type="application/rss+xml">`, even
when no RSS icon is displayed.
