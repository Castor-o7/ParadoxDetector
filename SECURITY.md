# Threat model

Paradox Detector reads text written by the people it investigates, spends API quotas that belong to its operator, and
can hand its output to an AI. This page says what can go wrong with each of those, what the code does about it, and what
is still open.

It covers the code as it stands. Items marked *open* are real gaps, not plans already met.

## What it protects and who it worries about

- **What matters:** API keys, API quotas, logs and scan history, the operator's trust in a score, and any agent or
  analyst acting on the output.
- **Who it worries about:** an attacker who controls text in a feed or log, including the IP being investigated; anyone
  who can reach the web server; and an AI client that has been talked into misusing the tools.
- **Not covered:** someone who already has a shell as the user running the detector. They can read `.env` directly.

**What leaves the machine.** Every scan sends the IP to the beacons, including VirusTotal, AbuseIPDB, OTX and GreyNoise.
Log lines aren't sent to them, but the fact that an IP appeared in your logs is visible to those services through the
lookup. The analyst summary sends the report to Anthropic, and only when it's asked for.

## Quota exhaustion

**Threat:** each scan queries every beacon, so anyone who can trigger scans spends your free-tier allowance. An attacker
can do this without reaching the app at all, because `paradox watch` scans each new public IP it sees in a log. Forged
source addresses in a log become lookups. When a quota runs out, the beacon goes quiet, the slow tier gets thinner and
an IP's paradox can rise.

**What's in place:**

- VirusTotal stays inside its free limits, with lookups spaced 15 seconds apart, daily and monthly caps, and an hour's
  reuse of good answers. The count is shared by processes on one machine.
- The web server limits scans and summaries per client (`PARADOX_RATE_LIMIT`, default 20 a minute) and runs at most 2
  log scans at once, each up to 50 IPs and 5 MB.
- `paradox watch` scans at most 15 new IPs an hour (`--max-new-per-hour`). A flood can still delay or hide a real
  attacker that appears only once, and the limit resets when the watcher restarts.
- A report lists each beacon that gave no reading, why, and what that costs, so a thin result says so.

**Open:**

- Only VirusTotal has a budget. The other beacons rely on their providers' own limits.
- Rescans of tracked IPs aren't capped, so a long tracked list can still reach VirusTotal's daily limit.
- The rate limit is in memory and per client, so it resets on restart and many clients get many allowances. With
  `PARADOX_TRUST_PROXY=1` it trusts `X-Forwarded-For`, which is only safe when a proxy sets that header.
- Lookups made with the same key on another machine aren't counted.

## Poisoned feeds

**Threat:** beacons are third-party opinions, and attackers can write to some of them. They can smear an innocent IP
with new OTX accounts, launder a bad one by getting it onto an allowlist, pad a pulse to trigger the bulk discount, or
forge a reverse DNS name.

**What's in place:**

- Sources sharing an upstream count as one vote, and a veneer contradiction must come from a different origin than the
  label it contradicts.
- Reverse DNS identity claims are forward-confirmed, and a forged one raises a veneer.
- Pulses that only mention an IP as contacted count at half weight, a small number of AbuseIPDB reporters gets scaled
  down unless the reports are recent, and one VirusTotal vendor can't flag an IP alone.
- The ledger shows the points behind a score, so an odd result can be traced to a beacon.

**Open:**

- `tests/test_adversarial.py` pins how far each attack moves a score. With independent beacons, laundering, padding and
  a forged PTR don't clear a malicious IP. But when OTX is the only witness, [5 new accounts can take a clean IP to
  Likely malicious](ROADMAP.md#38-smearing-by-new-otx-accounts--m), [OTX's own whitelist can clear real
  evidence](ROADMAP.md#39-otxs-whitelist-clearing-its-own-evidence--s), and [padding every pulse hides it](ROADMAP.md#310-padded-pulses-hiding-otx-only-evidence--s).
- Those tests use synthetic fixtures and attacks we thought of, so they don't show what a real attacker can do.
- One-vendor scaling has a cost: an attacker known to exactly one vendor and nothing else can read as Likely benign.
- Independence between VirusTotal's vendors can't be shown, because their sources are closed.

## Injection into the summarizer and MCP clients

**Threat:** pulse titles, tags, reverse DNS names and log lines can say anything, including instructions to an AI.
A user agent or SSH username is enough. An injected agent could also try to use the detector's tools as a way to read
local files.

**What's in place:**

- The summarizer's system prompt tells the model to treat beacon text as data, and the report is sent as JSON.
- MCP output schemas mark every field that can carry third-party text with `"x-untrusted": true`, every returned string
  is capped at 1,000 characters, and `redact` returns an allowlist of numbers and the detector's own fields.
- `scan_log` returns IPs and counts, never log lines.
- `scan_log`'s `path` reads only inside `/var/log` or the folders in `PARADOX_LOG_DIRS`. Symlinks and `..` can't leave
  them, and a refusal doesn't reveal whether a file exists.
- The web UI escapes third-party text, and the server sends a Content Security Policy that blocks framing and scripts
  from other origins. It allows inline scripts, so it wouldn't stop injected inline script if escaping failed.

**Open:**

- A label and a system prompt are requests, not enforcement. A model can still follow injected text, and how often
  isn't measured ([PDX-16](ROADMAP.md#41-prompt-injection-evaluation-for-the-analyst-summary--m)). Nothing checks a
  summary against the score yet ([PDX-17](ROADMAP.md#42-structured-verdict-free-text-second--s)). Read the score, not
  just the prose.
- `x-untrusted` only helps a client that acts on it.
- `scan_ip` and `scan_log` make network calls and spend quota whenever an agent asks, and only the VirusTotal pacing
  limits that on the MCP path.
- An allowed folder is readable in full, so its files' IPs and counts can reach the agent.

## Webhook data exposure

**Threat:** `paradox watch --webhook` posts alerts to a third party, often a shared chat channel. The payload can carry
more than people expect.

**What's in place:**

- The Slack-compatible `text` field holds only the flag, IP, scores and verdict. The raw `sample` log line is removed
  from everything posted, and appears only in `--json` stdout on your own machine.
- The watcher won't start with a webhook that isn't `https://` or `http://` on loopback, and the refusal doesn't quote
  the URL.
- Webhooks are opt-in, and a failed post is reported on stderr without stopping the watcher.

**Open:**

- A post still says which IPs were seen, how often, and the log's path (`source`), and the receiver can store all of it.
- `text` can quote a third-party label in the verdict, so a chat channel or bot reading it sees attacker-influenced text.
- The URL is effectively a password for its channel. `PARADOX_WEBHOOK` keeps it off the command line, but `--webhook`
  still works and would show it in process listings and shell history.
- `PARADOX_WEBHOOK_ALLOW_HTTP=1` allows unencrypted posts when someone sets it, and a server's redirect is followed
  without this check.

## `.env` handling

**Threat:** `.env` holds every API key and the web password. Leaking it spends your quotas under your name and opens
the web app.

**What's in place:**

- `paradox init` creates it with mode 600, and loading a file that others can read prints a warning with the fix.
- It's in `.gitignore` and `.dockerignore`, so it stays out of commits and images. Compose passes it at runtime.
- Status output reports whether a key is set, never its value.
- `scan_log` can't read it by default, because the working folder isn't allowed.

**Open:**

- A loose `.env` only gets a warning on stderr. It still loads, so a keys file others can read keeps working.
- Windows has no such check, and a container's `env_file` is read by Docker, not this check.
- Keys are held in plain text and in the process environment.
- A key pasted into a chat or an AI session should be treated as exposed and rotated.

## Why the server refuses to bind publicly without a password

**Threat:** the web app runs scans. On a public address with no password, anyone who finds it can spend your API quotas
and Anthropic credits, read your scan history, and upload logs for scanning. Scan history shows which IPs you've been
looking at, which an attacker under investigation would like to know.

**What's in place:**

- It binds to `127.0.0.1` by default. For any other address it exits with an error unless `PARADOX_PASSWORD` is set, so
  the safe outcome doesn't depend on reading the docs.
- `PARADOX_ALLOW_OPEN=1` overrides that, for when a proxy already handles auth. It has to be set on purpose.
- The password check uses a constant-time comparison, and log uploads must be JSON.

**Open:**

- HTTP Basic sends the password with each request and the server has no TLS of its own, so a public deployment needs an
  HTTPS proxy.
- `PARADOX_ALLOW_OPEN=1` behind a misconfigured proxy is an open server.
- On loopback there's no password, so anything else running on the machine can use the app.
