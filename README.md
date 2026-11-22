# Cyber security & OSINT watch

A self-hosted daily intelligence brief. It reads 121 public sources, removes the noise, scores what matters for a given organisation, and sends one e-mail — every morning at 06:00.

No dashboard, no account, no SaaS. A Python script, two GitHub Actions workflows, and your inbox.

---

## What it does

Every morning, the report arrives with:

| Section | Content |
|---|---|
| **Top priorities** | The five most dangerous items of the day, all sources merged |
| **Still relevant** | KEV entries first seen 3 to 14 days ago and still worth attention |
| **Alerts & Vulnerabilities** | Per source: CISA KEV, GitHub Advisory, NVD, national CERTs, vendor advisories |
| **Dark web & Ransomware** | Claimed victims, leak sites, French breach trackers |
| **News & Media · Threat Intelligence · Blogs & OSINT** | Long-form analysis and press, scored and deduplicated |
| **Your stack** | Box, Slack, Teams, Outlook, Microsoft 365, QRadar, Avigilon — only items with a real security signal |
| **European focus** | The same items, regrouped by the countries where IBM operates — 29 entries, EU included |
| **National CERT & trusted sources** | A ready index of the footprint's 29 entries, EU included, so you know where to look next |
| **Exploited by vendor** | KEV entries of the last 30 days, grouped by vendor |
| **Trend** | Seven-day comparison, volume, severity split, most active sources |

Each line carries what you actually need to triage it: severity badge, country flags, product affected, MITRE technique, actor, EPSS probability, CVSS score, reference links, and — when several outlets covered the same story — how many of them did.

---

## How relevance is decided

Scoring is deliberately simple and shows its arithmetic:

```
CVE cited            +3      actively exploited     +6
zero-day             +4      active campaign        +3
ransomware           +3      threat report          +3
named actor          +2      mass impact            +3
your stack           +2      country of interest  +3 / +1
target product       +2      breach with PII      +5 / +8
```

- **🔴 critical** at 10 points, **🟠 important** at 5.
- **Cross-source coverage** overrides age: three independent sources covering the same CVE on the same day earn +3 and escape any penalty. A lone exploit for a four-year-old flaw is capped just below critical; a two-year-old flaw that four outlets suddenly discuss is not.
- **Deduplication** works on links and on CVE sets. A story carried by five outlets appears once, with `Also covered by:` listing the others.

The aim is not to rank vulnerabilities by CVSS — it is to rank them by how much they concern *your* organisation, today.

---

## Sources

**114 RSS feeds and 7 API collectors**, in five families:

```
CERT & institutions   CERT-FR, CERT-EU, CISA, NCSC-NL, BSI, CERT-SE, NCSC UK…
Vendors & labs        Cisco PSIRT, Palo Alto, AWS, Cloudflare, Microsoft, Elastic,
                      Unit 42, SentinelOne, Rapid7, Malwarebytes, Bitdefender…
Press & analysis      BleepingComputer, The Record, SecurityWeek, The Hacker News,
                      Krebs, Dark Reading, CSO, Infosecurity, Next, 01net, Zataz…
Exploit & CVE feeds   Sploitus, CVEfeed, oss-security, GitHub Advisory, Metasploit
Ransomware            Ransomware.live, RansomLook, FrenchBreaches, Databreaches
```

Collectors query APIs rather than feeds: **CISA KEV**, **GitHub Advisory**, **Ransomware.live**, **Have I Been Pwned**, **EUVD (ENISA)**, **NVD** (23 vendors) and **Metasploit** (newly armed modules, computed as a diff against the previous run).

Enrichment is cached and optional: **EPSS** from FIRST, **CVSS and the affected product** from the NVD CPE, and aggregate campaign statistics. A source that fails never blocks the report — it is listed in an amber banner, and a source that stops publishing is reported separately from one that answers with an error.

---

## How it runs

Two GitHub Actions workflows, no server:

```
main.yml     05:58, 07:28, 08:58 UTC   the daily report
alerte.yml   every 3 hours             immediate alerts
```

State lives on a dedicated `data` branch — seen links, a SQLite history, API caches — committed as a single force-pushed commit. That keeps `main` clean and makes a fresh clone fully functional.

Three safety nets worth knowing about:

- **One report per day.** If the 05:58 run succeeded, the later slots exit in seconds. `forcer: true` (or `FORCE_VEILLE=1`) overrides it — useful for a manual test.
- **Dead man's switch.** Each run pings Healthchecks.io. If no ping arrives in 24 h, you get told the bot itself is down, rather than assuming a quiet day.
- **Alert mode.** The 3-hourly workflow only mails on genuinely urgent items: 14 points, or 5 if the product is in your stack. It reuses the same collectors with an 8-hour window, so an actively exploited CVE reaches you within three hours instead of waiting for the morning.

---

## Getting started

```bash
pip install -r requirements.txt
```

Three variables are mandatory, everything else has a sane default:

```bash
EMAIL_USER          # SMTP account, e.g. bot@gmail.com
EMAIL_PASSWORD      # app password, not your account password
RECIPIENT_EMAIL     # where the report goes
```

Optional, but they change the experience: `NVD_API_KEY` (CVSS lookups go from 6 s to 0.7 s apart), `RANSOMWARE_API_KEY`, `HEALTHCHECK_URL` and `HEALTHCHECK_URL_ALERTE`.

Then a first run:

```bash
python veille.py
```

The first launch builds a baseline: KEV and Metasploit caches are filled and existing links are recorded, so the first report is smaller than the following ones. That is expected.

On GitHub, add the same names under **Settings → Secrets and variables → Actions**, and the workflows take over.

---

## Configuration

All values are environment variables, all optional:

| Variable | Default | Effect |
|---|---|---|
| `WINDOW_HOURS` | `27` | Look-back window; 24 h plus margin for schedule drift |
| `MAX_PER_SOURCE` | `30` | Items kept per source, highest score first |
| `MAX_EMAIL_ARTICLES` | `1000` | Hard cap on a single e-mail |
| `CORROBORATION_MIN` | `3` | Sources needed to corroborate a CVE |
| `ALERT_THRESHOLD` | `14` | Score that triggers an immediate alert |
| `ALERT_STACK_THRESHOLD` | `5` | Same, for a product in your stack |
| `FORCE_VEILLE` | — | `1` sends a report even if one already went out |

Your own organisation is described in three places at the top of `veille.py`: `KEYWORDS_TARGETS` (products and vendors you care about), `STACK_PRODUCTS` (your actual tooling) and `COUNTRIES` (the footprint used by the European section). Editing those three lists is what turns a generic news digest into a watchlist.

---

## Tests

```bash
python _check_veille.py     # offline, no network, ~50 named checks
pytest                      # the same ground, through pytest
```

The offline suite covers scoring, deduplication, CVE extraction, country and stack detection, feed edge cases (undated entries, HTML served instead of XML, moved addresses) and the silence detection. It runs in a second and needs no credentials, which is why it sits in front of every commit.

---

## What this is not

It is not a vulnerability scanner, not a SIEM, and not a threat-intelligence platform. It does not touch the dark web or connect to any closed forum. It reads public feeds and APIs, and formats what it finds.

It also has opinions: a two-year-old exploit ranks below a fresh exploitation, three outlets matter more than one, and a product in your stack is worth more than a product you do not run. Those choices live in the scoring function, and they are meant to be edited.

---

## Support

If this tool saves you time, you can buy me a coffee:

**https://www.buymeacoffee.com/bsky.scl**

It funds the sources that cost money to query, and the occasional evening spent chasing a feed that quietly changed address.

---

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, adapt it to your own organisation.
