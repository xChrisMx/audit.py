#!/usr/bin/env python3

############################################################################################################
# Purpose: This python script consists of several attack surface mapping  and audit tools
#          to identify, assess and mitigate potential attack vectors.
#          This script is a work in progress and it will most likely continue to evolve.
#
# Usage:  python3 audit.py
#               or
#         chmod +x audit.py
#         ./audit.py
#
# Version: v. 0.7 - security/integrity hardening pass - 08/31/2026
#          v. 0.6 - added PQC/quantum-readiness audit, per-target logging, menu rewrite - 08/31/2026
#          v. 0.5 - added SQL audit support - 7/2/2025
#          v. 0.4 - added RDP Audit support - 6/20/2025
#          v. 0.3 - added Web vuln detection (nikto/nuclei) - 6/12/2025
#          v. 0.4 - added Masscan for 1-65,535 ports piped into nmap for service detection. - 07/22/2025
#          v. 0.5 - added enum4linux-ng for SMB enumeration
#
# Notice: 1. Ensure you are authorized to use this script.
#         2. Never use this script just for curiosity/irresponsibly. Reason should be legitimate.
#         3. Script can be noisy on some options (crawling, SQLMap). Scope before you run.
#
# Changes: 08/31/2026 (v0.7) - Final security/code/integrity pass: restored the lolcat Ctrl+C exit
#                       banner (now resolves /usr/games/lolcat as a fallback, since sudo's secure_path
#                       often drops /usr/games from PATH), grouped the target/exit options under their
#                       own "-- Options --" menu block, widened run()/capture() to catch any OSError
#                       (a missing-permission helper script no longer crashes the whole menu), closed
#                       a subprocess handle left open in ssl_audit, and fixed a stray loop-variable name.
#          08/31/2026 (v0.6) - Added the quantum-readiness (PQC) audit (option 10): probes HTTPS/SMTPS/
#                       SMTP+FTP+LDAP-STARTTLS/IMAPS/POP3S/FTPS/LDAPS/MQTT-TLS/AMQP-TLS/Kubernetes-API/
#                       SSH/RDP and classifies each as READY / CAPABLE / PLANNING REQUIRED / LEGACY
#                       (an internal, non-NIST framework - disclaimer prints with the report). IPsec,
#                       OpenVPN and WireGuard are intentionally NOT probed (no reliable black-box check
#                       exists for the first two; WireGuard has no PQ mode in mainline at all) - see
#                       manual_protocols_note(). Also added: per-target run logging under
#                       ./audit_logs/<target>/, a single reusable target prompt instead of re-asking
#                       per option, dropped the broken "run all" menu entry, fixed a shell-injection
#                       spot in ssl_audit's openssl|egrep pipe, fixed the sudo usage being applied
#                       inconsistently across tools, fixed nikto's -ask flag, made sqlmap actually
#                       test something by default (--crawl/--forms), and added testssl/httpx/nxc
#                       alongside (not instead of) the existing SSL/web/SMB tools.
############################################################################################################

import os
import pty
import re
import select
import shutil
import subprocess
import sys
import time
from datetime import datetime

###############################
#########CONFIGURATION#########
###############################

# COLORS
NORMAL = "\033[0m"
GREEN = "\033[1;32m"
YELLOW = "\033[33m"
RED = "\033[1;31m"
CYAN = "\033[36m"

# Absolute, not relative to CWD - this runs as an installed command (/usr/local/bin/audit)
# invoked from wherever the shell happens to be, which may not be writable.
LOG_ROOT = os.path.join(os.path.expanduser("~"), "audit_logs")

# Kex algorithms that indicate post-quantum / hybrid support in SSH.
SSH_PQ_KEX = ["mlkem768x25519-sha256", "sntrup761x25519-sha512"]
SSH_LEGACY_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]

# Candidate TLS 1.3 groups that indicate PQ/hybrid key exchange. Naming differs by OpenSSL
# version/provider (native ML-KEM landed in OpenSSL 3.5; older builds need oqs-provider's
# "Draft00" Kyber names). We probe them one at a time so one unrecognized name up front
# doesn't kill the whole check - see is_group_supported_locally().
PQ_TLS_GROUPS = [
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519Kyber768Draft00",
    "p256_kyber768",
]

# name, port, openssl -starttls keyword (None = implicit TLS, connect straight in)
TLS_QR_TARGETS = [
    ("HTTPS", 443, None),
    ("HTTPS-Alt (8443)", 8443, None),
    ("SMTPS", 465, None),
    ("SMTP STARTTLS (587)", 587, "smtp"),
    ("SMTP STARTTLS (25)", 25, "smtp"),
    ("IMAPS", 993, None),
    ("POP3S", 995, None),
    ("FTPS (implicit, 990)", 990, None),
    ("FTP STARTTLS (21)", 21, "ftp"),
    ("LDAPS", 636, None),
    ("LDAP STARTTLS (389)", 389, "ldap"),
    ("MQTT over TLS (8883)", 8883, None),
    ("AMQP over TLS (5671)", 5671, None),
    ("Kubernetes API (6443)", 6443, None),
]

##############################################
################GENERAL HELPERS##############
##############################################

_current_target = None
_current_logdir = None


def get_target():
    global _current_target, _current_logdir
    if _current_target is None:
        set_target()
    return _current_target


def set_target():
    global _current_target, _current_logdir
    _current_target = input("Enter a domain (or IP): ").strip()
    safe_name = re.sub(r"[^A-Za-z0-9.-]", "_", _current_target)
    logdir = os.path.join(LOG_ROOT, safe_name)
    try:
        os.makedirs(logdir, exist_ok=True)
        _current_logdir = logdir
        print(GREEN + f"[*] Target set to {_current_target} (logs -> {_current_logdir})" + NORMAL)
    except OSError as e:
        _current_logdir = None
        print(RED + f"[!] Target set to {_current_target}, but couldn't create log dir {logdir}: {e} "
                     f"- continuing without logging." + NORMAL)


def tool_available(name):
    if shutil.which(name) is None:
        print(RED + f"[!] '{name}' not found on PATH - skipping this check." + NORMAL)
        return False
    return True


def as_url(target, scheme="https"):
    """Most web tools need a scheme to know what to connect with - default to https since
    that's the common case today, but leave an explicit scheme (e.g. http, for a redirect
    check) or an already-full URL untouched."""
    return target if "://" in target else f"{scheme}://{target}"


def lolcat_cmd():
    """lolcat on Debian/Kali installs to /usr/games, which sudo's secure_path often excludes -
    check PATH first, then fall back to the known install location before giving up."""
    path = shutil.which("lolcat") or ("/usr/games/lolcat" if os.path.exists("/usr/games/lolcat") else None)
    return f"{path} -a -d 40" if path else None


def sudo_wrap(cmd):
    """Only the raw-socket / privileged tools (nmap scans, masscan wrapper, low-level SMB
    probes) get sudo-prefixed, and only when we're not already root. Everything else
    (nuclei/sqlmap/testssl/ssh-audit.py/etc.) is usually installed per-user via
    pip/pipx/go install, so blanket-sudo'ing them can break their PATH and silently no-op."""
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        return ["sudo"] + cmd
    return cmd


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


class LineLogger:
    """Turns raw pty output into a clean log: ANSI color codes stripped, and a run of \\r
    progress-bar overwrites collapsed down to just its final state instead of every frame."""

    def __init__(self, fileobj):
        self.f = fileobj
        self.buf = ""

    def feed(self, chunk_bytes):
        for ch in chunk_bytes.decode("utf-8", errors="replace"):
            if ch == "\r":
                self.buf = ""
            elif ch == "\n":
                self._flush_line()
            else:
                self.buf += ch

    def _flush_line(self):
        self.f.write((_ANSI_RE.sub("", self.buf) + "\n").encode("utf-8"))
        self.buf = ""

    def close(self):
        if self.buf:
            self._flush_line()


def run(cmd, step=None, timeout=None):
    """Run a command, stream it live, and tee a clean copy into the per-target log directory.

    Uses a pty (not a plain pipe) for the child's stdout/stderr: tools like masscan/nmap only
    emit their live "X% done, ETA" progress line when they think they're talking to a real
    terminal - piped output makes libc switch to full buffering and the progress just vanishes.
    A pty keeps that live behavior on screen; LineLogger cleans the copy that goes to disk.
    """
    print(CYAN + "$ " + " ".join(cmd) + NORMAL)
    logfile = None
    if step and _current_logdir:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        logfile = open(os.path.join(_current_logdir, f"{stamp}_{step}.log"), "ab")
    logger = LineLogger(logfile) if logfile else None

    master_fd = slave_fd = proc = None
    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(cmd, stdout=slave_fd, stderr=slave_fd)
        os.close(slave_fd)
        slave_fd = None

        deadline = time.monotonic() + timeout if timeout else None
        while True:
            wait_for = 0.5 if deadline is None else max(0, min(0.5, deadline - time.monotonic()))
            ready, _, _ = select.select([master_fd], [], [], wait_for)
            got_data = False
            if ready:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    got_data = True
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.flush()
                    if logger:
                        logger.feed(chunk)
            if not got_data and proc.poll() is not None:
                break
            if deadline and time.monotonic() > deadline:
                proc.kill()
                print(RED + f"[!] '{cmd[0]}' timed out after {timeout}s" + NORMAL)
                break
        proc.wait()
    except OSError as e:
        print(RED + f"[!] Failed to run '{cmd[0]}': {e}" + NORMAL)
    finally:
        for fd in (slave_fd, master_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if logger:
            logger.close()
        if logfile:
            logfile.close()


def capture(cmd, timeout=8):
    """Run a command and just return (returncode, combined_output) without streaming/logging.
    Used by the quantum-readiness probes, which make a lot of small throwaway calls."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout)
        return proc.returncode, proc.stdout.decode(errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


##############################################
##############PORT AUDIT########################
##############################################

def port_audit():
    domain = get_target()
    print("")
    print(YELLOW + f"Running MASSCAN on all 65535 ports and piping results to nmap for service identification {domain}" + NORMAL)
    run(sudo_wrap(["/data/scripts/port/portaudit.sh", domain]), step="port_audit")
    print("")


##############################################
##############SSH AUDIT########################
##############################################

def ssh_audit():
    domain = get_target()
    print("")
    print(YELLOW + f"Checking for SSHv1 support, Algos, Hostkey, Banner and Auth-methods {domain}" + NORMAL)
    run(sudo_wrap(["nmap", "--script", "banner,sshv1,ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
                   "-p", "22", domain]), step="ssh_nmap")
    print("")

    print(YELLOW + f"Running Detailed SSH Cipher audit {domain}" + NORMAL)
    run(["python3", "/data/scripts/ssh/ssh-audit/ssh-audit.py", domain], step="ssh_audit_py")
    print("")


##############################################
##############SSL Audit########################
##############################################

def ssl_audit():
    domain = get_target()
    print("")
    print(YELLOW + f"Pulling Server, Intermediate CA and Root CA certs {domain}" + NORMAL)
    run(["/data/scripts/ssl/acert-linux", "-port", "443", "-host", domain], step="cert_pull")
    print("")

    print(YELLOW + f"Checking OpenSSL Cipher negotiation on {domain}" + NORMAL)
    p1 = subprocess.Popen(["openssl", "s_client", "-connect", f"{domain}:443"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL)
    out = subprocess.run(["egrep", "-i", "(TLS|SSL|Protocol|Cipher)"],
                          stdin=p1.stdout, capture_output=True, text=True)
    p1.stdout.close()
    p1.wait()
    print(out.stdout)
    print("")

    print(YELLOW + f"Running Detailed SSL/TLS Cipher audit via SSLSCAN {domain}" + NORMAL)
    run(sudo_wrap(["sslscan", "--iana-names", domain]), step="sslscan")
    print("")

    print(YELLOW + f"Running Detailed SSL/TLS Cipher audit via SSLYZE {domain}" + NORMAL)
    run(sudo_wrap(["sslyze", domain]), step="sslyze")
    print("")

    if tool_available("testssl"):
        print(YELLOW + f"Running testssl full audit (protocols, ciphers, cert chain, known vulns) on {domain}" + NORMAL)
        run(["testssl", "--full", f"{domain}:443"], step="testssl")
        print("")


##############################################
##############RDP Audit########################
##############################################

def rdp_audit():
    domain = get_target()
    print("")
    print(YELLOW + f"Running RDP Sec Check on {domain}" + NORMAL)
    run(["/data/scripts/rdp/rdp-sec-check.pl", domain], step="rdp_sec_check")
    print("")

    print(YELLOW + f"Enumerating RDP protocol via NMAP and TESTSSL on {domain}" + NORMAL)
    run(sudo_wrap(["/data/scripts/rdp/rdpaudit.sh", domain]), step="rdp_nmap_testssl")
    print("")


##############################################
##############What Web########################
##############################################

def _web_recon_common(domain):
    print(YELLOW + f"Checking if host is behind a DNS/HTTP Load Balancer {domain}" + NORMAL)
    run(["lbd", domain], step="lbd")  # lbd wants a bare hostname, not a URL
    print("")

    print(YELLOW + f"Identifying Redirects on {domain}" + NORMAL)
    # Deliberately http:// here (not as_url()'s https default) - the point of this check is
    # to see whether the site redirects http -> https, so we want to start from plain http.
    run(["curl", "-sSik", as_url(domain, scheme="http")], step="curl_redirects")
    print("")


def what_web():
    domain = get_target()
    _web_recon_common(domain)

    print(YELLOW + f"Running Web App Firewall Fingerprinting on {domain}" + NORMAL)
    run(["wafw00f", as_url(domain)], step="wafw00f")
    print("")

    print(YELLOW + f"Running a WhatWeb Technology scan on {domain}" + NORMAL)
    run(sudo_wrap(["whatweb", "-v", "--colour=always", as_url(domain)]), step="whatweb")
    print("")

    if tool_available("httpx"):
        print(YELLOW + f"Running httpx for fast tech/status/title/redirect-chain fingerprinting on {domain}" + NORMAL)
        # No scheme forced here on purpose - httpx probes both http and https itself when given
        # a bare host, which is strictly better than us picking one for it.
        run(["httpx", "-u", domain, "-title", "-status-code", "-tech-detect", "-follow-redirects"],
            step="httpx")
        print("")


##############################################
################Web Vulns###################
##############################################

def web_vulns():
    domain = get_target()
    _web_recon_common(domain)

    print(YELLOW + f"Running Nuclei on {domain}" + NORMAL)
    run(["nuclei", "-u", as_url(domain)], step="nuclei")
    print("")

    print(YELLOW + f"Running Nikto {domain}" + NORMAL)
    # nikto -host defaults to plain HTTP on port 80 unless given a full URL (or -ssl/-port) -
    # without this it would silently miss an HTTPS-only target.
    run(["nikto", "-ask", "no", "-host", as_url(domain)], step="nikto")
    print("")


##############################################
#################Ping Sweep###################
##############################################

def ping_sweep():
    domain = get_target()
    print("")
    print(YELLOW + f"Running ICMP Echo Ping on {domain}" + NORMAL)
    run(sudo_wrap(["nmap", "-sn", "-PE", domain]), step="ping_icmp")
    print("")

    print(YELLOW + f"Running TCP SYN Ping on {domain}" + NORMAL)
    run(sudo_wrap(["nmap", "-sn", "-PS22-25,80,113,442,445,8080", domain]), step="ping_syn")
    print("")

    print(YELLOW + f"Running TCP ACK Ping on {domain}" + NORMAL)
    run(sudo_wrap(["nmap", "-sn", "-PA", domain]), step="ping_ack")
    print("")

    print(YELLOW + f"Running UDP Ping on {domain}" + NORMAL)
    run(sudo_wrap(["nmap", "-sn", "-PU", domain]), step="ping_udp")
    print("")


##############################################
##############SQL AUDIT########################
##############################################

def sql_audit():
    domain = get_target()
    url = as_url(domain)
    print("")
    print(YELLOW + f"Note: sqlmap needs a full URL (scheme included) to connect at all - using {url}. "
                    "It also only tests parameters it can see: a bare URL with no query string gives it "
                    "nothing to test, so --crawl/--forms below let it find its own injection points, at "
                    "the cost of more requests. If you already know a specific page/parameter worth "
                    "targeting, set the target to that full URL instead (e.g. https://host.com/page?id=1) "
                    "via option 't'." + NORMAL)
    print(YELLOW + f"Scanning for SQL injection vulnerabilities... {url}" + NORMAL)
    run(["sqlmap", "--batch", "--random-agent", "--crawl=2", "--forms",
         "--level", "2", "--risk", "1", "-u", url], step="sqlmap")
    print("")


##############################################
##############SMB ENUM########################
##############################################

def smb_enum():
    domain = get_target()
    print("")
    print(YELLOW + f"Running enum4linux-ng against {domain}" + NORMAL)
    run(["enum4linux-ng", "-A", domain], step="enum4linux")
    print("")

    print(YELLOW + f"Testing anonymous share enumeration on {domain}" + NORMAL)
    run(sudo_wrap(["smbclient", "-L", f"//{domain}", "-N"]), step="smbclient_shares")
    print("")

    print(YELLOW + f"Testing anonymous IPC$ access on {domain}" + NORMAL)
    run(sudo_wrap(["smbclient", f"//{domain}/ipc$", "-N", "-c", "quit"]), step="smbclient_ipc")
    print("")

    print(YELLOW + f"Running SMB Enumeration via Nmap against {domain}" + NORMAL)
    run(sudo_wrap([
        "nmap", "-Pn", "-p", "445",
        "--script", "smb-protocols,smb2-security-mode,smb2-capabilities,smb-os-discovery,smb-enum-shares,smb-enum-users",
        domain]), step="smb_nmap")
    print("")

    if tool_available("nxc"):
        print(YELLOW + f"Running netexec (nxc) anonymous SMB check (shares + signing) on {domain}" + NORMAL)
        run(["nxc", "smb", domain, "-u", "", "-p", "", "--shares"], step="nxc_smb")
        print("")


##############################################
############QUANTUM READINESS AUDIT###########
##############################################
#
# Categories (internal Keysight framework, defined by the operator - see disclaimer at the
# end of the report):
#   READY             - hybrid or post-quantum key exchange actually negotiated
#   CAPABLE           - PQ/hybrid support is advertised but wasn't the one negotiated
#   PLANNING REQUIRED - modern classical crypto only (secure today, no PQ story yet)
#   LEGACY            - outdated protocol/cipher/software, needs upgrading regardless of PQC
#
# Scope note: TLS-wrapped protocols (HTTPS and friends, LDAPS, FTPS, MQTT/AMQP-TLS, the
# Kubernetes API) and SSH are checked directly below. IPsec, OpenVPN and WireGuard are NOT
# probed - see manual_protocols_note() for why, and don't trust a scanner that claims otherwise.

def is_group_supported_locally(group):
    """Ask our own openssl if it even knows this TLS group name before we blame the target.
    Connects to a well-known closed local port - a fast connection-refused error means openssl
    accepted the -groups argument fine; an argument-parsing error means it doesn't know the name."""
    rc, out = capture(["openssl", "s_client", "-groups", group, "-connect", "127.0.0.1:1"], timeout=3)
    if rc is None:
        return False
    return not re.search(r"unknown group|error setting|error with -groups", out, re.I)


def tls_pq_probe(name, host, port, starttls):
    base = ["openssl", "s_client", "-connect", f"{host}:{port}", "-tls1_3"]
    if starttls:
        base += ["-starttls", starttls]

    # Reachability check up front so an unreachable host doesn't cost us one timeout per PQ group.
    rc, out = capture(base, timeout=6)
    if rc is None or ("CONNECTED" not in out and "errno" in out.lower()):
        return name, "UNREACHABLE", None
    if not re.search(r"TLSv1\.3", out):
        if re.search(r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|RC4|NULL-|EXPORT", out, re.I):
            return name, "LEGACY", "weak protocol/cipher negotiated, no TLS1.3"
        return name, "PLANNING REQUIRED", "no TLS1.3 negotiated, can't carry a PQ group"

    for group in PQ_TLS_GROUPS:
        rc, out = capture(base + ["-groups", group], timeout=6)
        if rc is None:
            continue
        if re.search(r"unknown group|error setting|error with -groups", out, re.I):
            continue  # our local openssl doesn't know this group name - not the target's fault
        m = re.search(r"Server Temp Key:\s*(\S+)", out)
        if m and re.search(r"MLKEM|KYBER", m.group(1), re.I):
            return name, "READY", m.group(1)

    return name, "PLANNING REQUIRED", "TLS1.3, classical key exchange only - no PQ group negotiated"


def ssh_pq_probe(host):
    rc, algos_out = capture(["nmap", "-p", "22", "--script", "ssh2-enum-algos", host], timeout=15)
    if rc is None or "kex_algorithms" not in algos_out.lower():
        return "UNREACHABLE", None

    offered_pq = [a for a in SSH_PQ_KEX if a in algos_out]
    offered_legacy_only = all(kex in algos_out for kex in SSH_LEGACY_KEX) if not offered_pq else False

    if offered_pq:
        kexlist = ",".join(SSH_PQ_KEX)
        rc, out = capture(["ssh", "-vv", "-o", "PreferredAuthentications=none",
                            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                            "-o", f"KexAlgorithms={kexlist}", host], timeout=10)
        if rc is not None and re.search(r"Authentications that can continue|Permission denied", out):
            return "READY", ", ".join(offered_pq)
        return "CAPABLE", ", ".join(offered_pq)

    if offered_legacy_only:
        return "LEGACY", "group1/group14-sha1 only"
    return "PLANNING REQUIRED", "modern classical kex only, no PQ kex offered"


def os_fingerprint(host):
    if not tool_available("nmap"):
        return "unknown (nmap not available)"
    rc, out = capture(sudo_wrap(["nmap", "-O", "--osscan-guess", host]), timeout=25)
    if rc is None:
        return "unknown"
    m = re.search(r"OS details:\s*(.+)", out)
    if m:
        return m.group(1).strip()
    m = re.search(r"Aggressive OS guesses:\s*(.+)", out)
    return m.group(1).strip() if m else "undetermined (closed/filtered ports or guess below confidence threshold)"


def manual_protocols_note():
    print(YELLOW + "Not scanned (see why below):" + NORMAL)
    print("  IPsec/IKEv2  - PQ key exchange (RFC 9370 multiple-KE, draft ML-KEM) is new and "
          "vendor-specific; there's no reliable black-box CLI probe for it yet. Check the "
          "VPN gateway vendor's documentation directly.")
    print("  OpenVPN      - the control channel handshake needs OpenVPN-specific framing before "
          "TLS starts, so generic tools (openssl s_client, testssl) can't reach it. Check "
          "server config / OpenSSL version it was built against.")
    print("  WireGuard    - not a gap in our tooling: mainline WireGuard has no PQ/hybrid mode "
          "at all, it's fixed Curve25519+ChaCha20Poly1305 by design. Treat any WireGuard "
          "endpoint as LEGACY for PQ purposes unless it's layered with something like Rosenpass.")
    print("")


def print_qr_table(rows):
    color = {"READY": GREEN, "CAPABLE": CYAN, "PLANNING REQUIRED": YELLOW,
             "LEGACY": RED, "UNREACHABLE": NORMAL}
    print(f"{'CHECK':<26}{'STATUS':<20}{'DETAIL'}")
    print("-" * 80)
    for name, status, detail in rows:
        c = color.get(status, NORMAL)
        print(f"{name:<26}{c}{status:<20}{NORMAL}{detail or '-'}")
    print("")


QR_DEFINITIONS = [
    ("READY", GREEN, "Hybrid or post-quantum key exchange is actually negotiated - already ready today."),
    ("CAPABLE", CYAN, "The OS or software supports PQC, but it's not enabled yet."),
    ("PLANNING REQUIRED", YELLOW, "Modern crypto but no PQC support yet. Strong against today's threats, "
                                   "but not post-quantum ready."),
    ("LEGACY", RED, "Outdated crypto or unsupported software - needs upgrading regardless of PQC."),
]


def print_qr_legend():
    print(GREEN + "-- Category definitions --" + NORMAL)
    for label, color, meaning in QR_DEFINITIONS:
        print(f"{color}{label:<20}{NORMAL}{meaning}")
    print("")


def quantum_check():
    domain = get_target()
    print("")
    print(YELLOW + f"Running quantum-readiness (PQC) audit against {domain}" + NORMAL)
    print(YELLOW + "This opens a probe connection per protocol/port checked - expect it to take a minute or two." + NORMAL)
    print("")

    if not tool_available("openssl"):
        print(RED + "[!] openssl not found - TLS-based checks will be skipped entirely." + NORMAL)

    local_pq_support = [g for g in PQ_TLS_GROUPS if is_group_supported_locally(g)]
    if not local_pq_support:
        print(RED + "[!] Local openssl doesn't recognize any of our candidate PQ/hybrid TLS "
                     "group names (needs OpenSSL 3.5+, or an older build with oqs-provider "
                     "installed). TLS checks below will only be able to report LEGACY/PLANNING "
                     "REQUIRED, never READY, until this box's openssl is upgraded." + NORMAL)
    print("")

    rows = []
    for name, port, starttls in TLS_QR_TARGETS:
        rows.append(tls_pq_probe(name, domain, port, starttls))

    if tool_available("ssh"):
        status, detail = ssh_pq_probe(domain)
        rows.append(("SSH (22)", status, detail))

    print(YELLOW + f"RDP (3389): TLS is wrapped behind an RDP connection preamble, so it can't be "
                    f"probed with openssl directly. Best-effort only." + NORMAL)
    if tool_available("testssl"):
        rc, out = capture(["testssl", "--quiet", "-t", "rdp", f"{domain}:3389"], timeout=20)
        if rc is None:
            rows.append(("RDP (3389)", "UNREACHABLE", "testssl has no RDP support in this build"))
        else:
            rows.append(("RDP (3389)", "PLANNING REQUIRED" if "TLS1" in out else "LEGACY",
                         "classical-only check via testssl, PQ group not confirmable"))
    else:
        rows.append(("RDP (3389)", "UNREACHABLE", "testssl not installed"))

    print("")
    print(GREEN + "=== Quantum-Readiness Summary ===" + NORMAL)
    print_qr_table(rows)

    manual_protocols_note()

    print(YELLOW + f"OS fingerprint (best-effort, nmap -O): {os_fingerprint(domain)}" + NORMAL)
    print("")

    print_qr_legend()

    print(CYAN + "Note: READY / CAPABLE / PLANNING REQUIRED / LEGACY are an internal Keysight "
                  "assessment framework used for this audit only - this is not an official NIST "
                  "PQC certification or endorsement." + NORMAL)
    print("")


##############################################
###############MENU FUNCTION##################
##############################################

CATEGORIES = [
    ("Recon", [
        ("1", "Port audit (masscan+nmap, 65k ports)", port_audit),
        ("2", "Ping sweep (ICMP/SYN/ACK/UDP)", ping_sweep),
    ]),
    ("Protocol", [
        ("3", "SSH audit", ssh_audit),
        ("4", "SSL/TLS audit", ssl_audit),
        ("5", "RDP audit", rdp_audit),
        ("6", "SMB enumeration", smb_enum),
    ]),
    ("Web/App", [
        ("7", "Web tech fingerprint", what_web),
        ("8", "Web vuln scan (nikto/nuclei)", web_vulns),
        ("9", "SQLMap injection audit", sql_audit),
    ]),
    ("Crypto", [
        ("10", "Quantum-readiness (PQC) audit", quantum_check),
    ]),
]

ACTIONS = {key: fn for _, items in CATEGORIES for key, _, fn in items}


def print_menu():
    print(YELLOW)
    print("################################################################")
    print("#   audit.py - A small collection of Keysight Auditing Tools   #")
    print("#   Ver: 0.7 - Author: CM                                      #")
    print("################################################################")
    print(NORMAL)
    target = _current_target or "(not set)"
    for cat, items in CATEGORIES:
        print(GREEN + f"-- {cat} --" + NORMAL)
        for key, label, _ in items:
            print(f"{key}) {label}")
    print(GREEN + "-- Options --" + NORMAL)
    print(f"t) Set/change target (current: {target})")
    print("q) Exit")
    print("")


def menu():
    while True:
        print_menu()
        op = input("Choose an option: ").strip().lower()
        if op == "q":
            break
        elif op == "t":
            set_target()
        elif op in ACTIONS:
            ACTIONS[op]()
        else:
            print("Choose a valid option")


# LAUNCH SCRIPT
try:
    menu()
except KeyboardInterrupt:
    print()
    lolcat = lolcat_cmd()
    if lolcat:
        subprocess.run(f'echo "[!] Ctrl + C Detected... Exiting script." | {lolcat}', shell=True)
    else:
        print("[!] Ctrl + C Detected... Exiting script.")
