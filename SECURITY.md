# Security policy

## Supported versions

This project is a single script, not a library. Only the latest commit on `main` is supported — there are no maintained branches and no backports.

## Secret scanning

Provider credentials are covered the usual way: secret scanning and push protection are both on, so an AWS, GitHub, OpenAI or Stripe key pasted by mistake is blocked at the push, before it ever reaches the history.

Two things are missing, and **not by oversight**. GitHub reserves them for *organization-owned* repositories carrying Secret Protection:

- **generic patterns** — private keys, connection strings, credentials without a known provider;
- **validity checks** — whether a detected credential is still live.

This repository sits under a personal account, so neither is offered: the settings page hides them and the REST API answers `200` while silently ignoring both fields. That is what a feature unavailable to a given account type looks like, and no plan changes it — only moving the repository into an organization would.

The gap is closed by [`gitleaks`](https://github.com/gitleaks/gitleaks) instead, with its default rules:

- `verifier.yml` scans every pull request, so a secret cannot be merged into `main`;
- `scripts/hooks/pre-commit`, once enabled with `git config core.hooksPath scripts/hooks`, stops it before the commit that would make it part of the history.

Both report nothing on the current tree and history. If you find a way around either check, that is in scope — see below.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use the **Report a vulnerability** button under the repository's *Security* tab. That opens a private advisory visible only to you and the maintainer, which is the right place to discuss a flaw, a proof of concept, or a suggested fix.

If private reporting is not available, open an issue containing only the words *"security issue, requesting a private channel"* — with no technical detail — and a private channel will be arranged.

## What to expect

This is a personal project maintained on personal time:

- **Acknowledged** within a few days.
- **Assessed** with a clear verdict: accepted, out of scope, or duplicate.
- **Fixed** as soon as reasonably possible when accepted, with credit in the commit message unless you prefer otherwise.

There is no bug bounty, no CVE-issuing process, and no formal SLA.

## In scope

Anything that lets an attacker do something the tool's own logic would not:

- **Secret disclosure** — a token, password or key reaching a log, an e-mail, a commit or a cached file.
- **Injection into the report** — crafted feed content executing as HTML or JavaScript in the rendered e-mail, or breaking the MIME structure.
- **Remote code execution or path traversal** triggered by fetched content.
- **Denial of service** on the workflow — a source able to hang or crash a run indefinitely, or to exhaust the runner.
- **Supply-chain** — a dependency or a pinned action that could be swapped for a malicious one.

## Out of scope

- **The content of the sources.** A feed publishing a false or exaggerated story is a source problem, not a vulnerability.
- **Your own deployment.** An SMTP password in a plaintext file, an overly broad personal access token, a forked workflow that prints secrets — those are configuration decisions in your own copy.
- **Third-party services** queried by the tool (NVD, FIRST, GitHub, Ransomware.live). Report those to their operators.
- **Volume or relevance complaints.** A feed that floods the report, or a score you disagree with, is a normal issue — the scoring lists are meant to be edited.

## Good faith

Someone who reports a flaw privately, avoids accessing data that is not theirs, and gives reasonable time to fix it before publishing, will get a constructive answer and public credit.

---

*This project is licensed under the MIT licence; it comes with no warranty, including fitness for any particular purpose.*
