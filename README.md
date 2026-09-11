Usage: 
- python3 xrecon.py
* or
- chmod +x xrecon.py and ./xrecon.py

Latest version includes Dmitry and Fierce.  This script was made for a project of my needs, feel free to modify/contribute as needed.

Tools built in script:
- Nikto/Nuclei (detect web app vulns; poor man's scanner :D)
- SSH Algos, wafw00f (web app FW fingerprinting), curl (to identify redirects), lbd (to detect if DNS or HTTP load balancer is used, OpenSSL cipher negotiation.
- Ping Sweep (~95% host detection rate; if you are not sure if an ip is live or not this will detect if there is anything live behind an IP)
- What Web (Identify Web Technologies used)
- Dmitry (DNS  Deep Info Gathering tool -- Catch subdomains, email addresses, uptime info, etc).
- Fierce (DNS Interrogation tool used to locate non-contiguous IP spaces and hostnames against specified domains or subdomains).  This tool alone will probably yield a bunch of vuln hosts.

Screenshot:
![image](https://github.com/user-attachments/assets/bc0a4408-2132-4650-90de-8b5dd5d917d9)


---------------------------------

# audit.py

An interactive menu that wraps a collection of external pentest tools
(nmap, masscan, sslscan/sslyze/testssl, sqlmap, nikto/nuclei, enum4linux-ng,
ssh-audit, rdp-sec-check, and a few in-house scripts) behind a single
target prompt and a consistent live-output/logging convention — not a
scanner in its own right, but a front end that saves re-typing the same
target/flags into a dozen different tools during an engagement. Unlike its
siblings (`ssh_vuln_scan.py`, `sslspray.py`, `snmp_tftp_audit.py`, etc.),
this one is interactive/menu-driven rather than a batch sweep over a
subnet list, and it drives real installed CLI tools rather than talking to
targets directly.

## What it does

One target (domain or IP) is set once, then reused across every menu
option until changed. Options are grouped by category:

**Recon**
- Port audit — masscan across all 65,535 ports piped into nmap for service ID (via `/data/scripts/port/portaudit.sh`)
- Ping sweep — ICMP echo, TCP SYN, TCP ACK, and UDP ping via nmap

**Protocol**
- SSH audit — nmap banner/SSHv1/hostkey/auth-methods/algo scripts, plus a full `ssh-audit.py` cipher audit
- SSL/TLS audit — cert chain pull, `openssl s_client` protocol/cipher check, sslscan, sslyze, and testssl (if installed)
- RDP audit — `rdp-sec-check.pl` plus an nmap+testssl RDP wrapper script
- SMB enumeration — enum4linux-ng, anonymous share/IPC$ probes via smbclient, nmap SMB scripts, and netexec (`nxc`, if installed)

**Web/App**
- Web tech fingerprint — load-balancer detection (`lbd`), redirect check, WAF fingerprinting (`wafw00f`), WhatWeb, and httpx (if installed)
- Web vuln scan — nuclei and nikto
- SQLMap injection audit — crawls/tests forms on the target URL

**Crypto**
- Quantum-readiness (PQC) audit — see below

Every option calls `get_target()` first, so the first menu choice in a
session prompts for a target; every one after that reuses it until `t` is
used to change it.

## Quantum-readiness (PQC) audit

The newest and most involved option. It probes TLS-wrapped protocols
(HTTPS, HTTPS-alt/8443, SMTPS, SMTP/FTP/LDAP STARTTLS, IMAPS, POP3S, FTPS,
LDAPS, MQTT-TLS, AMQP-TLS, the Kubernetes API) plus SSH and (best-effort)
RDP, and classifies each into one of four buckets:

| Status | Meaning |
|---|---|
| **READY** | Hybrid or post-quantum key exchange actually negotiated |
| **CAPABLE** | PQ/hybrid support advertised (offered by the server or the OS/software) but not what was actually negotiated |
| **PLANNING REQUIRED** | Modern classical crypto only — secure today, no PQ story yet |
| **LEGACY** | Outdated protocol/cipher/software — needs upgrading regardless of PQC |

This is an **internal, non-NIST framework** the script prints a disclaimer
about at the end of every report — it is a working assessment convention
for this audit, not an official PQC certification.

**How TLS is checked**: `openssl s_client -tls1_3` connects first to
confirm TLS 1.3 is even negotiated (no TLS 1.3 → straight to LEGACY or
PLANNING REQUIRED depending on whether a weak protocol/cipher showed up).
If TLS 1.3 is present, each candidate PQ/hybrid group in `PQ_TLS_GROUPS`
(`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, plus the
older draft Kyber names for pre-3.5 OpenSSL/oqs-provider builds) is tried
one at a time via `-groups`, and the server's `Server Temp Key:` line is
checked for `MLKEM`/`KYBER`. Groups are probed individually specifically
so that one name your local openssl doesn't recognize doesn't kill the
whole check — `is_group_supported_locally()` pre-flights each name against
a closed local port before blaming the target for it.

**How SSH is checked**: `ssh2-enum-algos` lists offered kex algorithms;
if either post-quantum kex (`mlkem768x25519-sha256`,
`sntrup761x25519-sha512`) is offered, a follow-up `ssh -vv` connection
attempt with `KexAlgorithms` pinned to those checks whether the kex
actually completes (→ READY) or just gets offered (→ CAPABLE). No PQ kex
but only legacy `diffie-hellman-group1/14-sha1` → LEGACY; anything else →
PLANNING REQUIRED.

**RDP is best-effort only** — RDP wraps TLS behind its own connection
preamble, so it can't be probed with `openssl s_client` directly; the
script falls back to `testssl -t rdp` (classical-only signal, can't
confirm a PQ group) when testssl is installed, and reports UNREACHABLE
otherwise.

**Deliberately not probed**: IPsec/IKEv2 (no reliable black-box CLI check
exists yet for RFC 9370 multi-KE/draft ML-KEM), OpenVPN (its control
channel needs OpenVPN-specific framing before TLS starts, so generic tools
can't reach it), and WireGuard (not a tooling gap — mainline WireGuard has
no PQ/hybrid mode at all; it's fixed Curve25519+ChaCha20Poly1305 by
design, so treat any WireGuard endpoint as LEGACY for PQ purposes unless
it's layered with something like Rosenpass). `manual_protocols_note()`
prints this reasoning at the end of every quantum-readiness report so it's
never mistaken for silent scan failure.

An OS fingerprint (`nmap -O --osscan-guess`, best-effort) is included in
the report for context, since OS/crypto-library version is often the
actual blocker behind a PLANNING REQUIRED or LEGACY result.

## Requirements

This script assumes a fully-provisioned Kali-style box — most options
reference tools by name on PATH, and several reference custom in-house
scripts by **absolute path**:

- `/data/scripts/port/portaudit.sh` (port audit)
- `/data/scripts/ssh/ssh-audit/ssh-audit.py` (SSH cipher audit)
- `/data/scripts/ssl/acert-linux` (cert pull)
- `/data/scripts/rdp/rdp-sec-check.pl`, `/data/scripts/rdp/rdpaudit.sh` (RDP audit)

If `/data/scripts/...` doesn't exist on the box this runs on, those
specific options will fail — everything else (anything invoking a
PATH-resolved tool) is independent of that layout.

External tools used directly from PATH: `nmap`, `masscan` (via
portaudit.sh), `openssl`, `sslscan`, `sslyze`, `sqlmap`, `nikto`,
`nuclei`, `wafw00f`, `whatweb`, `lbd`, `curl`, `enum4linux-ng`,
`smbclient`, `ssh`. Optional (checked with `tool_available()` and skipped
with a warning if missing, not fatal): `testssl`, `httpx`, `nxc`
(netexec). `lolcat` is optional cosmetic flair on the Ctrl+C exit banner
only — its Debian/Kali install path (`/usr/games/lolcat`) is checked
directly since sudo's `secure_path` commonly drops `/usr/games` from PATH.

Python 3 standard library only — no `pip install` needed for the script
itself (`pty`, so Linux/macOS only; no Windows support).

## Usage

```bash
python3 audit.py
# or
chmod +x audit.py
./audit.py
```

It's meant to be installed as `/usr/local/bin/audit` and run from
wherever the shell happens to be — hence logs go under
`~/audit_logs/<target>/`, not relative to the current working directory.

Set a target, then pick options from the menu; the target persists until
changed with `t`:

```
Enter a domain (or IP): example.com
[*] Target set to example.com (logs -> /home/user/audit_logs/example.com)

-- Recon --
1) Port audit (masscan+nmap, 65k ports)
2) Ping sweep (ICMP/SYN/ACK/UDP)
-- Protocol --
3) SSH audit
4) SSL/TLS audit
5) RDP audit
6) SMB enumeration
-- Web/App --
7) Web tech fingerprint
8) Web vuln scan (nikto/nuclei)
9) SQLMap injection audit
-- Crypto --
10) Quantum-readiness (PQC) audit
-- Options --
t) Set/change target (current: example.com)
q) Exit
```

Root/sudo is only requested for the raw-socket / privileged tools (nmap
scans that need it, masscan, low-level SMB probes) via `sudo_wrap()` — and
only when not already running as root. Everything else (nuclei, sqlmap,
testssl, ssh-audit.py, etc.) is left unprefixed on purpose, since those
are typically installed per-user via pip/pipx/`go install`, and
blanket-`sudo`-ing them can break their PATH and silently no-op.

## Output / logging

Every `run()`-based command (i.e. everything except the small
throwaway probes inside the quantum-readiness audit, which use the
lighter-weight `capture()`) is:

- **Streamed live to the terminal** through a pty, not a plain pipe —
  tools like masscan/nmap only emit their live "X% done, ETA" line when
  they think they're talking to a real terminal; piping switches libc to
  full buffering and the progress bar disappears.
- **Teed into a clean log file** under `~/audit_logs/<target>/`, named
  `<timestamp>_<step>.log` (one file per command, per run — re-running the
  same option creates a new timestamped file rather than overwriting).
  `LineLogger` strips ANSI color codes and collapses `\r`-driven
  progress-bar overwrites down to their final line before writing to disk,
  so the log reads like a normal scrollback rather than a wall of
  overwritten progress frames.

`<target>` in the log path is sanitized (`[^A-Za-z0-9.-]` → `_`) so a
hostname or IP can't escape the intended `~/audit_logs/` directory.

If the log directory can't be created (e.g. permissions), the run
continues without logging — target selection doesn't fail, only the
tee-to-disk step is skipped, with a warning printed at that point.

## Architecture notes

**One target, reused everywhere.** `get_target()`/`set_target()` hold a
single global target + log directory, set on first use and reused by
every subsequent option — replacing an earlier pattern (per the changelog)
of re-prompting for a target on every single menu choice.

**`run()` vs `capture()`.** `run()` is for the main menu options: live
pty streaming + logging, used when a human is meant to watch the tool
work. `capture()` is for the quantum-readiness audit's many small
probe connections (one openssl call per candidate PQ group, per protocol)
where streaming/logging every single throwaway connection attempt would
just be noise — it returns `(returncode, combined_output)` and nothing
else.

**Both catch a broad `OSError`, not just missing-binary cases** — a
helper script that exists but isn't executable (a permissions issue, not
a missing tool) raises `OSError` too, and the menu should report that and
move on rather than crash the whole session over one broken option.

**Per-target-run isolation.** Each `run()` call opens/closes its own pty
pair and log file; a subprocess crashing or a permission error on one
option doesn't affect the state of any other.

## Limitations

**Several options are hard-tied to `/data/scripts/...` absolute paths**
(port audit, SSH cipher audit, cert pull, RDP audit) — this script assumes
it's running on the specific box those were installed on. Porting it
elsewhere means either replicating that layout or swapping those calls
for PATH-resolved equivalents.

**No Windows support** — `pty` is POSIX-only; this is Linux/macOS-only by
design (matches the sibling scripts' Kali-box assumption).

**`sql_audit()`'s `--crawl=2 --forms`** finds its own injection points on
a bare URL, at the cost of more requests — if a specific
already-known vulnerable parameter is the target, set the target to that
full URL (`t` → `https://host.com/page?id=1`) rather than a bare host, per
the note the script itself prints before running sqlmap.

**RDP quantum-readiness is inherently best-effort** — no direct
openssl-based PQ-group check is possible through RDP's own preamble;
testssl's classical-only RDP check is the closest available signal, not a
PQ confirmation either way.

**No `--help`/CLI-flag interface** — every option is interactive-only
(menu selection + `input()` for the target); there's no way to script a
single audit option from the command line without going through the menu.

## Verification

This README and pass were produced from a full read-through of the
script's logic (menu wiring, `run()`/`capture()`/`LineLogger` streaming
and logging paths, the PQC classification logic for TLS and SSH, and the
absolute-path/tool-availability assumptions) — it has not been
independently re-executed against a live target as part of this pass.
The script's own changelog (v0.7, 2026-08-31) already documents a prior
security/integrity hardening pass (a shell-injection spot in `ssl_audit`'s
`openssl | egrep` pipe, inconsistent sudo usage, a stray loop-variable
name, and a subprocess handle left open) fixed before this README was
written.
