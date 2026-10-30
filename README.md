# Cyber Security Paradox Detector

[![CI](https://github.com/Castor-o7/ParadoxDetector/actions/workflows/ci.yml/badge.svg)](https://github.com/Castor-o7/ParadoxDetector/actions/workflows/ci.yml)

Give it a public IP. It queries several threat-intel beacons at the same time and scores how much the
**fast-updating** beacons disagree with the **slow-updating** ones.

A high **paradox score** usually means live sources (OTX pulses, sensor networks, botnet trackers)
see a threat that curated blocklists and vendor reputation haven't picked up yet. That's an emerging
threat that slips past slower defenses.

Where it's headed: [ROADMAP.md](ROADMAP.md), on unmasking borrowed legitimacy.

## Install

```bash
pipx install git+https://github.com/Castor-o7/ParadoxDetector   # or, from a checkout: pipx install .
paradox init        # creates your keys file (~/.paradox-detector/.env); every key is optional
paradox             # opens the app in your browser
```

You only need Python 3.10+. The core uses the standard library alone (`pipx install
"paradox-detector[narrative] @ git+…"` adds the optional Claude summaries). A beacon that needs a
missing key is skipped. `paradox beacons` shows which keys are set, and `paradox where` shows where
keys, history and caches live. Set `PARADOX_HOME` to move them. Run from a source checkout
(`python3 -m paradox …`), it keeps everything in the checkout instead.

## App and headless mode

`paradox` on its own is the **app**: it starts the local server and opens the UI. Every other
command is **headless**, for servers, cron, CI and AI agents. Each one prints plain text or `--json`
and exits with **0** (nothing flagged), **1** (something flagged as veneer, paradox or threat) or
**2** (bad input), so scripts can branch on the result.

| Command | What it does |
|---|---|
| `paradox` / `paradox app` | Open the app in your browser |
| `paradox serve` | Run the web UI and JSON API without opening a browser (what Docker runs) |
| `paradox scan IP [IP ...]` | Full report for one or more IPs (`--json`, `--narrate`) |
| `paradox log FILE` | Rank every IP in a log (`-` for stdin; `--csv`, `--json`) |
| `paradox watch --log FILE` | Sensor: follow logs live, scan new IPs, alert on findings |
| `paradox history IP` | Recorded scans and measured beacon lag |
| `paradox rescan` | Rescan every tracked IP once |
| `paradox mcp` | MCP server on stdio, for AI assistants |
| `paradox calibrate` | Check scores against labeled IPs |
| `paradox beacons` / `init` / `where` | Key status, create keys file, show storage paths |

```bash
paradox scan 45.155.205.233 --json | jq .score.paradox
paradox log /var/log/auth.log || echo "something in the auth log needs a look"
```

The old forms (`python3 -m paradox 1.2.3.4`, `--log`, `--history`, `--rescan-tracked`,
`python3 server.py`) still work.

### Watch mode

`paradox watch` is the headless sensor. It follows one or more logs like `tail -F`: it survives
log rotation and truncation, and waits for a file that doesn't exist yet. Each public IP is scanned
once it appears (or after `--min-hits N`), and again only after `--rescan-after` hours (default 24),
so a busy log doesn't hammer the beacons.

```bash
paradox watch --log /var/log/auth.log --log /var/log/nginx/access.log
paradox watch --log /var/log/auth.log --json --webhook https://hooks.slack.com/services/...
journalctl -fu sshd | paradox watch --log -
paradox watch --rescan-every 6             # no logs: keep tracked IPs fresh (replaces cron)
```

An alert fires when an IP's flag enters the alert set (`--alert-on`, default
`veneer,paradox,threat`) or changes, not on every sighting. Alerts go to stdout (one JSON object
per line with `--json`) and, with `--webhook`, are POSTed as JSON. The payload's `text` field works
as-is with Slack and Mattermost incoming webhooks. Log lines are untrusted, so
the attacker-written `sample` line is kept out of `text` and only appears in the JSON `alert`
object. `docker stop` and Ctrl+C shut it down cleanly. It exits 1 if anything alerted.

Developing: `python3 -m unittest discover -s tests` (no keys or network needed).

## Beacons

| Tier | Beacon | Key | What it contributes |
|---|---|---|---|
| fast | AlienVault OTX pulses | optional | Community pulses, weighted by recency (30-day half-life) |
| fast | GreyNoise Community | optional | Whether the IP is attacking internet sensors right now |
| fast | abuse.ch Feodo Tracker | none | Botnet C2 servers, updated every 5 minutes |
| fast | AbuseIPDB | required | Crowd abuse reports from the last 90 days |
| fast | abuse.ch ThreatFox | required | Malware IOCs |
| slow | Spamhaus DROP | none | Curated hijacked or criminal netblocks |
| slow | VirusTotal | required | Vendor blocklist consensus |
| slow | Shodan InternetDB + CISA KEV + FIRST EPSS | none | Weekly scan data, CVEs, known-exploited status, exploit likelihood |
| network | Neighborhood (/24, IPv6 /64) | none | Blocklisted neighbors from blocklist.de, CINS Army, ET compromised, Feodo, Spamhaus DROP |
| network | Network (ASN) via RIPEstat | none | ASN owner, Spamhaus ASN-DROP (criminal-run networks), hosting heuristic |
| context | RDAP, Tor exit list | none | Ownership and anonymizer status (not scored) |
| context | Reverse DNS identity | none | Forward-confirmed reverse DNS: verifies (or catches forging of) a claimed operator identity |
| context | Operator-published ranges | none | Address ranges that Googlebot, Bingbot, Applebot, GPTBot and Censys publish for their crawlers/scanners |

Bulk feeds (Feodo, DROP, KEV, Tor) are cached in the app's home directory (`paradox where`).

## How the score works

Each beacon produces a **threat** reading (0–1) and a **confidence** (0–1). A hit counts more than
"not listed".

1. **Tier score** is half the confidence-weighted mean of the tier and half its strongest confident
   detection. One solid hit matters, and silence from a narrow list only partly dilutes it.
2. **gap = fast − slow**
   - `emerging` (gap > 0): fast sources see something the slow ones don't. This counts at full weight.
   - `stale` (gap < 0): slow lists still flag the IP but nothing fresh is happening, so it may have been
     remediated or reassigned. This counts at half weight.
3. **Reputation veneer.** Attackers borrow legitimacy: cloud ranges, CDNs, "research scanner" labels.
   A benign label (GreyNoise RIOT/benign, OTX whitelist, AbuseIPDB whitelist) is recorded as a claim,
   not trusted outright. When a *different* beacon reports confident, fresh threat activity, the
   label loses half its weight and the paradox score goes up. A label with no fresh contradiction
   stays benign, so 8.8.8.8 and 1.1.1.1 still read as Coherent.
   - **Scanner labels explain scanning, nothing more.** Shodan's scanner collects thousands of
     port-scan reports for doing its job. When GreyNoise labels an IP a benign scanner, evidence that
     is mostly scanning is discounted by its scan share: AbuseIPDB report categories, and OTX pulse
     themes, where pulses that mention both scanning and attacks don't vote. Brute force, malware or
     C2 evidence is not explained and still triggers the veneer. Measured 2026-10-28: Shodan's
     scanner went from paradox 100 to 17, and a brute-forcer wearing the same label still scores 94.
   - **Claimed identities are verified.** Anyone can set an IP's reverse DNS to
     `census.shodan.io` or `crawl.googlebot.com`, but only the real operator can make that name
     resolve back to the IP. A forward-confirmed claim to a known scanner or crawler domain
     (`IDENTITY_DOMAINS` in `paradox/sources.py`) is a label. It gives the scanner rule a second
     source, so it keeps working when GreyNoise is rate-limited. A claim that doesn't resolve back
     is a **forged identity**: it triggers the veneer and sets a "Suspicious" threat floor.
     Operators that publish their ranges (`PUBLISHED_RANGES`) give a third source: an IP inside
     Censys's published list is a Censys scanner label. Lists are cached for a day, and a list that
     fails to load is reported but doesn't fail the scan. Shodan and Palo Alto Xpanse publish no
     public list, so Shodan relies on reverse DNS and Xpanse on GreyNoise alone.
   - **Labels never discount their own contradiction.** A GreyNoise RIOT "business service" label
     does not weaken OTX, or the veneer would protect itself.
   - **Shared infrastructure.** On AbuseIPDB "Content Delivery Network" addresses (GitHub,
     Microsoft, Google front ends), OTX counts at half weight. Their pulses are mostly research
     reports listing every IP the malware contacted. Usage type describes the network, not a vouch
     for the IP, and direct attack reports keep full weight.
4. **paradox = 100 × (0.8·directional gap + 0.2·dispersion + 0.25·veneer + 0.2·neighborhood cover) × coverage factor**.
   Coverage dampens the score when one tier barely answered.

### Neighborhood and network

Attackers rotate through adjacent addresses and rent from bulletproof hosts, so a clean IP in a
dirty block deserves suspicion. The **network** tier is scored separately from fast/slow, because
guilt by association is a different claim from direct evidence.

- **Neighborhood risk** counts blocklisted neighbors in the IP's /24. The first 2 are treated as
  background noise, since 97% of dirty /24s have fewer than 5. After that the risk climbs:
  5 neighbors give 0.31, 10 give 0.63, 20 give 0.9. Partial Spamhaus DROP coverage of the block sets
  a floor of 0.7.
- **Cloud/hosting networks** (matched by ASN name) count neighborhood risk at half strength,
  because neighbors there are unrelated tenants. A network on Spamhaus ASN-DROP never gets that
  discount, since it is bulletproof hosting.
- **Effect on scores:** `cover = max(0, network risk − the IP's own threat)` adds up to 20 points to
  the paradox. The overall threat score is raised to at least half the network risk, so an ASN-DROP
  network alone reads as "Likely malicious".
- **Explanations adapt.** A stale reputation on a cloud network mentions that the IP may belong to a
  previous tenant. A stale reputation on an ASN-DROP network reads as dormancy, not cleanup.

### Calibration

`paradox calibrate` scores a labeled set of IPs and reports how well the scores separate
them. Labels never come from the score's own inputs:

- **Malicious:** IPs on at least 2 of blocklist.de, CINS Army and ET compromised. Those lists only
  feed the neighborhood check, which excludes the IP itself. IPs on Feodo or Spamhaus DROP are left
  out.
- **Benign:** public DNS resolvers and the front-end IPs of major sites.

**Research scanners.** Scanning blocklists also list research scanners, which are reported for
doing what they say they do. The headline numbers stay strict and count every sampled IP as
malicious. A secondary **scanner-aware** view sets aside IPs with a scanner label and reports them
as their own class, with the detector's verdict on each: `explained` (a known scanner doing
scanning), `veneer` (doing more than scanning) or `unexplained`. The scanner label is itself a score
input, so the scanner-aware view would hide the scanner rule's cost if it replaced the strict one.
On the 2026-10-29 data it found Shodan (via GreyNoise and reverse DNS) and Palo Alto Xpanse (via
GreyNoise), both `explained`. The other 28 malicious IPs: AUC 1.000, detection 100%.

Raw OTX responses are saved, so OTX settings (`OTX_*` in `paradox/sources.py`) and the scoring weights
can be re-tested offline with `--rescore`, with no API calls. `--refresh <beacon ...>` re-runs
just those beacons on the saved scans, keeping the old reading wherever a call fails. If OTX starts rate-limiting, the run
stops early and fills in the gaps next time.

Results (30 malicious, 25 benign IPs):

| | Run 1 (no keys) | Run 3 (AbuseIPDB, OTX down) | Run 4 (all live) | Run 5 (scanner + CDN rules) |
|---|---|---|---|---|
| Ranking (AUC) | 0.95 | 1.00 | 1.00 | 0.995 |
| Malicious detected | 97% | 100% | 100% | 97% |
| Benign flagged | 56% | 4% | 16% | 12% |
| Benign with paradox ≥ 35 | 28% | 0% | 4% | 0% |

Run 4 had OTX, AbuseIPDB and keyed GreyNoise live (GreyNoise's community tier still returned 429
on 20 of 55 scans). Four of its five benign flags come from OTX alone, on Quad9, Google, GitHub
(paradox 46) and Microsoft, all from large multi-author pulse sets. The fifth is Netflix's 37%
AbuseIPDB confidence. No slow-tier beacon flagged a benign IP.

Run 5 re-scored the same data (AbuseIPDB refreshed with `--refresh abuseipdb`) after the scanner
and shared-infrastructure rules. GitHub dropped from 45 to 15 and Microsoft from 34 to 15. The one
new "miss" is 80.82.77.139, Shodan's own scanner, which is in the malicious set only because
scanning blocklists include research scanners. It now reads as a known scanner doing scanning,
which is the intended verdict. Quad9's secondary resolver (paradox 23) and Netflix (26) still show
mild tension. Caveat: no malicious IP in the set sits on a CDN, so this data can't measure the CDN
rule's downside (for example, a phishing site behind Cloudflare).

What calibration changed:

- **Bulk pulses are discounted.** Benign infrastructure (DNS resolvers, GitHub, Apple, CDNs) showed
  up in huge sandbox pulses listing thousands of indicators, because malware contacts those services.
  Pulses about malicious IPs were small and targeted. Pulses with more than 1,000 indicators now
  count for much less.
- **OTX's whitelist suppresses OTX's own pulses** (×0.2). The veneer check still fires when an
  independent source disagrees.
- **The automated-feed discount stays.** Removing it didn't help detect any malicious IP and pushed
  GitHub to a "Paradox" score.
- **`.env` inline comments were being read as key values.** Fixed.

Caveats: OTX's keyless quota ran out during run 3, so the OTX changes were checked on saved responses
for 8 IPs rather than all 55. GreyNoise was rate-limited throughout. Run again with `OTX_API_KEY` and
`GREYNOISE_API_KEY` set for a full picture. GitHub, Quad9 and Microsoft still score "Mild tension",
which is defensible because malware really does use them.

### Source independence

Some sources share upstream data, and two copies of one observation shouldn't look like corroboration:

- **Shared origins are one vote.** Feodo Tracker and ThreatFox both come from abuse.ch, so they are
  merged before scoring. The merged reading is their weighted mean, and its weight is that of the
  strongest member. Set `origin` on a beacon in `BEACONS` to declare others.
- **VirusTotal is de-duplicated.** Vendors this app already queries directly (AlienVault, abuse.ch,
  Spamhaus, GreyNoise, AbuseIPDB) are dropped from VirusTotal's count and listed as "not
  double-counted".
- A veneer contradiction must come from a different *origin* than the label it contradicts.

### History and lag

Every fresh scan is saved to `history.sqlite3` in the app's home directory. For each IP, the app records when each beacon
first flagged it (threat ≥ 0.4 at confidence ≥ 0.5) and reports either how long the slow tier took to
catch up or how long the paradox has been open. The web UI charts fast vs. slow scores over time.

Timelines need repeated scans. Leave `paradox watch --rescan-every 6` running, or use cron:

```cron
0 */6 * * * paradox rescan
```

### OTX hardening

Anyone can publish an OTX pulse, so pulses are scored for independence and quality, not just counted:

- **One vote per author.** Each author counts once, using their best pulse. Ten pulses from one
  account can't inflate an IP's score or smear it.
- **Quality discounts.** Automated feeds ×0.6, clones ×0.3, test/junk names ×0.3, and pulses with
  few subscribers count for less.
- **Recency.** Pulses lose half their weight every 30 days.
- **Confidence** grows with the number of distinct authors, not the number of pulses.

Labels: <15 Coherent, <35 Mild tension, <60 Paradox, ≥60 Severe paradox. The overall **threat** score
is reported separately. An IP that every beacon agrees is malicious has high threat and a low paradox.

Every report carries a **ledger**: signed points that add up to the paradox and threat scores, plus what the
rules changed about a beacon before it voted. The CLI, web UI and MCP tools all show it.

You can tune tiers and weights in `paradox/sources.py` (`BEACONS`) and the constants in `paradox/scoring.py`.

## Batch log scanning

Point it at any log (web, SSH, firewall, JSON lines, CSV). It finds every public IPv4/IPv6 address,
scans the most active ones, and ranks them by how much attention they deserve:

1. **Veneer**: a trusted label (scanner, whitelist) that fresh evidence contradicts
2. **Paradox**: paradox ≥ 35
3. **Threat**: threat ≥ 40
4. **Watch**: mild tension or suspicious

```bash
paradox log /var/log/auth.log                    # table
journalctl -u sshd | paradox log - --limit 40     # from stdin
paradox log access.log --min-hits 5 --csv > triage.csv
```

Private and reserved addresses are counted and skipped. `--limit` (default 25, `0` for all) caps how
many IPs get scanned, most active first, because each IP queries every beacon. The command exits
with status 1 when anything is flagged veneer, paradox or threat, so scripts and CI can react.
The web app has the same feature under **Scan a log** (paste or pick a file up to 5 MB, max 50 IPs).

## MCP server

`paradox mcp` puts the detector back where the class prototype started: as tools an AI
assistant can call. It speaks MCP over stdio using only the standard library.

| Tool | What it does |
|---|---|
| `scan_ip` | Full paradox report for one IP |
| `scan_log` | Rank the IPs in log text or a local log file |
| `ip_history` | Recorded scans and measured beacon lag |
| `beacon_status` | Which beacons are configured and which keys are set |

Register it with Claude Code:

```bash
claude mcp add paradox -- paradox mcp
```

Or in any client's JSON config:

```json
{"mcpServers": {"paradox": {"command": "paradox", "args": ["mcp"]}}}
```

**Prompt-injection hygiene.** Pulse titles, tags and log lines are written by third parties,
sometimes by the attacker under investigation (a user agent or SSH username can say anything).
Tool results label beacon text as data rather than instructions, and `scan_log` returns only IPs
and counts, never the log lines themselves.

## Deploying the web app

The server is safe on localhost by default. Exposing it means anyone who reaches it can spend your
API quotas (and Anthropic credits, if narratives are on), so it has guards:

- **`PARADOX_PASSWORD`** turns on HTTP Basic auth (any username). The server refuses to bind a
  non-loopback address without it, unless `PARADOX_ALLOW_OPEN=1` says a proxy already handles auth.
- **Rate limit**: `PARADOX_RATE_LIMIT` scans/summaries per client per minute (default 20). Set
  `PARADOX_TRUST_PROXY=1` behind a reverse proxy so the limit applies per real client.
- **`/healthz`** is the only unauthenticated route.
- Security headers (CSP, `nosniff`, no-referrer, no framing). Log uploads must be JSON
  (`Content-Type: application/json`), which also blocks cross-site form posts.
- API keys stay on the server and never reach the browser.

### Docker

```bash
cp paradox/env.example .env   # add keys and PARADOX_PASSWORD
docker compose up -d --build
docker compose run --rm web paradox scan 45.155.205.233 --json   # any headless command
```

Compose runs two services that share one volume: `web` (`paradox serve`, published on
127.0.0.1:8787) and `watch` (`paradox watch --rescan-every 6`, so history and lag fill in without
cron). The compose file shows how to mount host logs into `watch` and add a webhook. `.env` is in
`.dockerignore` and is passed at runtime, never baked into the image. The container runs as an
unprivileged user.

### Going public

Put a TLS reverse proxy in front, because Basic auth over plain HTTP sends the password in the
clear. With [Caddy](https://caddyserver.com), the whole config is:

```
paradox.example.edu {
    reverse_proxy 127.0.0.1:8787
}
```

Then set `PARADOX_TRUST_PROXY=1`. A 25-IP log scan can take a few minutes (5 IPs took 43 s here), so log scans run as background
jobs that the page polls, so proxy timeouts don't cut them off.

## CI/CD

| Workflow | Runs on | What it does |
|---|---|---|
| `ci.yml` | every PR and push to main | Tests on Python 3.10, 3.12, 3.13 (Linux) and 3.14 (native macOS), then installs `paradox` away from the checkout and checks its exit codes |
| `docker.yml` | every PR and push to main | Builds the image, waits for it to report healthy, checks the password guard and API, proves no keys file, scan history or source tree ships and that it runs unprivileged. On main, publishes `ghcr.io/castor-o7/paradoxdetector:latest` and `:<short sha>` |
| `release.yml` | pushing a `v*` tag | Checks the tag matches both version strings, builds and test-installs the wheel, creates a GitHub Release with the wheel and sdist, and publishes `:<version>` and `:<major.minor>` images |
| `calibrate.yml` | by hand (Actions tab) | Live calibration on a fresh labeled set. Posts the metrics to the run summary and uploads the report. Beacon keys are optional repository secrets |

PR runs cancel the run they supersede, every job has a timeout, and every action is pinned to a
commit SHA, which Dependabot keeps current. To release:

```bash
# bump version in pyproject.toml and paradox/__init__.py, merge, then:
git tag v0.3.0 && git push origin v0.3.0
```

To run the published image instead of building: `docker pull ghcr.io/castor-o7/paradoxdetector:latest`.

## Analyst summary (optional)

`pip install anthropic`, then set `ANTHROPIC_API_KEY`. The web UI's **Generate with Claude** button and
`--narrate` in the CLI send the scored report to Claude (`claude-opus-5-5` by default), which writes a
short verdict, explains why the beacons disagree, and recommends next steps.

## Layout

```
paradox/cli.py        the `paradox` command: app + headless subcommands
paradox/sources.py    beacon adapters -> Signal
paradox/scoring.py    tier scores, paradox, threat
paradox/engine.py     concurrent scan + caching
paradox/history.py    SQLite scan history + lag measurement
paradox/logscan.py    batch mode: extract IPs from logs, scan, rank
paradox/watch.py      headless sensor: follow logs, alert, periodic rescans
paradox/server.py     stdlib HTTP server + JSON API (/api/scan, /api/logscan, /api/history, ...)
paradox/web/          single-page UI
paradox/mcp_server.py MCP server (stdio JSON-RPC) exposing the scanner as tools
paradox/narrative.py  optional Claude summary
paradox/calibrate.py  scoring checked against labeled IPs
paradox/env.example   keys file template (paradox init)
pyproject.toml        packaging; installs the `paradox` command
Dockerfile, docker-compose.yml   container deployment (serve + watch)
examples/             sample log for trying batch mode
```
