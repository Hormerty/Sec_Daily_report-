# Cyber security & OSINT watch

A self-hosted daily intelligence brief **built for a European footprint**. It reads 121 public sources, removes the noise, scores what matters for a given organisation, and sends one e-mail — every morning at 06:00.

No dashboard, no account, no SaaS. A Python script, three GitHub Actions workflows, and your inbox.

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

## Built around a European footprint

This is not a global feed reader with a European filter bolted on: the orientation is in the design.

- **European focus is the section that matters.** Every item mentioning a country of the footprint is regrouped there, so a German advisory about a French subsidiary does not disappear among two hundred headlines. The footprint has 29 entries, EU included, and lives in `COUNTRIES`.
- **The national CERTs of the footprint are queried directly** — CERT-FR and ANSSI, CERT-EU, BSI, NCSC-NL, CERT-SE, CCB, CIRCL, CSIRT Italia, INCIBE, NCSC UK, NSM and the others — and the report always closes with their index, even on a quiet day. That is the part that tells you where to look next.
- **ENISA's EUVD** collector runs alongside CISA's KEV, so the European vulnerability database is covered, not only the American one.
- **French-language sources are read in French**, never machine-translated — Next, 01net, Zataz, Korben, Clubic, IT-Connect, FrenchBreaches, Le Monde Informatique — because a French breach rarely reaches the English press.
- **NIS2, GDPR, RGPD, DORA** are recognised keywords, and the Benelux plus France weigh more heavily than a passing mention of another country.

Change `COUNTRIES` to your own perimeter and the section follows. The default is Europe — Belgium, France and their neighbours first — because that is where the reader sits.

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

Three GitHub Actions workflows, no server:

```
main.yml      05:58, 07:28, 08:58 UTC   the daily report
alerte.yml    every 3 hours             immediate alerts
verifier.yml  every pull request        the offline checks, blocking
```

The third one touches no state and needs no secret: it installs the dependencies, then runs the offline checks and `pytest` on every pull request and every push to `main`. Its job is to make a dependency bump or a contributor's patch fail *before* the merge rather than in the 06:00 run.

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

### Secrets you must provide

The tool sends mail through SMTP, so it needs a mail account. Three secrets are mandatory — there is no default that would let it run without them. A fourth, `GITHUB_TOKEN`, is supplied by Actions and must not be created.

| Secret | Required | What it is | Where to get it |
|---|---|---|---|
| `EMAIL_USER` | **yes** | The account the report is sent from | Your provider, e.g. `mywatch@gmail.com` |
| `EMAIL_PASSWORD` | **yes** | An **application password** — never the account password | Gmail: Account → Security → 2-step verification → App passwords. Any provider offering SMTP works |
| `RECIPIENT_EMAIL` | **yes** | Where the report is delivered, usually the same address | — |
| `GITHUB_TOKEN` | **automatic** | Supplied by Actions and used by the GitHub Advisory collector. **Never create it, never store it yourself** | — |
| `NVD_API_KEY` | no | Raises the NVD rate limit: one CVSS lookup every 0.7 s instead of every 6.5 s, so 30 per run instead of 10 | <https://nvd.nist.gov/developers/request-an-api-key> |
| `RANSOMWARE_API_KEY` | no | Adds victim claims and group names from Ransomware.live | <https://www.ransomware.live/> |
| `HEALTHCHECK_URL` | no | Dead man's switch for the daily report, 24 h period. **Must be a different UUID from the alert one** | <https://healthchecks.io/> |
| `HEALTHCHECK_URL_ALERTE` | no | Second, separate check for the 3-hourly run, 3 h period. **Must be a different UUID from the daily one** | <https://healthchecks.io/> |

> ⚠️ **The two healthcheck URLs are read by the workflows, not by the script** — they are a `curl` at the end of each job, not a variable the Python reads. Point both at the same UUID and a failed daily report will look exactly like a quiet alert run: you lose the only signal that tells you the bot itself has stopped.
>
> ⚠️ **Nothing in this table is ever committed.** `.env` is already in `.gitignore`, and a leaked token is revoked at the provider, never simply edited out of a file — git remembers.

### Where to put them

Locally, export them in your shell — or keep a `.env` file you never commit:

```bash
export EMAIL_USER="mywatch@gmail.com"
export EMAIL_PASSWORD="xxxx xxxx xxxx xxxx"
export RECIPIENT_EMAIL="me@example.com"
```

On GitHub, under **Settings → Secrets and variables → Actions → New repository secret**, with exactly these names. The workflows pass them to the script; nothing else has to be configured.

### SMTP defaults

Gmail is the default. For another provider:

| Variable | Default | Notes |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | Your SMTP server |
| `SMTP_SECURITY` | `ssl` | or `starttls` |
| `SMTP_PORT` | `465` with `ssl`, `587` with `starttls` | Adjust if your provider differs |
| `EMAIL_ENCODING` | `base64` | `8bit` sends a smaller message when the server accepts it |

### First run

Then a first run:

```bash
python veille.py
```

The first launch builds a baseline: KEV and Metasploit caches are filled and existing links are recorded, so the first report is smaller than the following ones. That is expected, not a bug.

On GitHub, once the secrets are in place, the workflows take over — no further setup.

---

## Configuration

All values are environment variables, all optional:

| Variable | Default | Effect |
|---|---|---|
| `WINDOW_HOURS` | `27` | Look-back window; 24 h plus margin for schedule drift |
| `MAX_PER_SOURCE` | `30` | Items kept per source, highest score first |
| `MAX_EMAIL_ARTICLES` | `1000` | Hard cap on a single e-mail |
| `MAX_EMAIL_BYTES` | `0` | Size cap; `0` means no cap |
| `CORROBORATION_MIN` | `3` | Sources needed to corroborate a CVE |
| `MAX_CVSS` | `30` / `10` | CVSS lookups per run, depending on `NVD_API_KEY` |
| `ALERT_THRESHOLD` | `14` | Score that triggers an immediate alert |
| `ALERT_STACK_THRESHOLD` | `5` | Same, for a product in your stack |
| `ALERT_MAX` | `5` | Items per alert e-mail; the rest waits for the next slot |
| `FORCE_VEILLE` | — | `1` sends a report even if one already went out |
| `IGNORE_SEEN` | `1` | `0` replays items already delivered |

Your own organisation is described in three places at the top of `veille.py`: `KEYWORDS_TARGETS` (products and vendors you care about), `STACK_PRODUCTS` (your actual tooling) and `COUNTRIES` (the footprint used by the European section). Editing those three lists is what turns a generic news digest into a watchlist.

### Adding a product to your stack

`STACK_PRODUCTS` maps a name — the one printed in the report — to the phrases that identify it, lower-case and matched on word boundaries. One entry is enough: the report header, the stack section and the alert threshold all follow from the dict.

```python
STACK_PRODUCTS["GitLab"] = ["gitlab", "gitlab ci", "gitlab runner", "gitlab self-managed"]
```

Two things worth knowing before adding one:

- **The words you choose decide the noise.** `box` and `teams` needed guards in the code — *black box*, *box office*, *security teams* — and `outlook` needed a filter for every market study titled *Threat Outlook 2027*. A bare common word matches everything. Give the phrase, not the word: `box drive`, not `box`.
- **A stack hit is loud by design.** Any article naming the product scores +2, and the alert threshold drops from 14 to 5, so a careless keyword turns the 3-hourly alert into a newsletter. Add the product you actually run, not the one you keep reading about.

The dict order is the order the sections appear in the report, and each one keeps at most six articles per run, 24 in total.

---

## Tests

```bash
python _check_veille.py     # offline, no network, ~50 named checks
pytest                      # the same ground, through pytest
```

The offline suite covers scoring, deduplication, CVE extraction, country and stack detection, feed edge cases (undated entries, HTML served instead of XML, moved addresses) and the silence detection. It runs in a second and needs no credentials, which is why `verifier.yml` runs it on every pull request and every push to `main`. A red check stays red on the pull request — and, on a public repository, the commit that would break the morning report is stopped at the door rather than discovered at 06:00.

A fourth step in the same workflow guards the secrets themselves. GitHub scans provider credentials on public repositories for free, but the **generic** patterns — private keys, connection strings — are reserved for organization-owned repositories, and this one sits under a personal account. [`gitleaks`](https://github.com/gitleaks/gitleaks) covers that ground instead, with its default rules. The same check can run before the commit rather than after the push:

```bash
git config core.hooksPath scripts/hooks   # once, from the repository root
```

It needs `gitleaks` on your `PATH`; without it the hook says so and lets the commit through, and CI still does the check.

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
