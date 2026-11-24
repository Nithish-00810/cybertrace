"""
CyberTrace defensive analysis tools.

Safety rules enforced here:
  * Submitted URLs are PARSED, never fetched.
  * Evidence files are READ as data, never executed.
  * Every tool returns {tool, status, data | error, evidence_refs}.
  * Only the AbuseIPDB reputation call touches the network, and only when a key is configured.
"""
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

MAX_INPUT_CHARS = 2_000_000
SEV_POINTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
WEIGHT = {"observed": 1.0, "intel": 1.0, "heuristic": 0.6}

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
SYSLOG_TS = re.compile(r"[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}")
HOUR_RE = re.compile(r"(\d{2}):\d{2}:\d{2}")
AUTH_CTX = re.compile(r"login|log in|logon|auth|password|ssh|session|sign[- ]?in|credential|sudo|account", re.I)
FAIL_RE = re.compile(r"fail|denied|invalid|unauthori[sz]ed|refused|wrong password|bad password|locked", re.I)
OK_RE = re.compile(r"accept|success|succeeded|logged in|granted|authenticated", re.I)
USER_RE = re.compile(r"(?:\buser[=:\s]+|\bfor (?:invalid user )?)([A-Za-z0-9._@-]{1,64})", re.I)

TS_KEYS = ["timestamp", "time", "@timestamp", "datetime", "date", "eventtime"]
USER_KEYS = ["user", "username", "user_name", "account", "principal"]
IP_KEYS = ["ip", "src_ip", "source_ip", "client_ip", "remote_addr", "src", "ip_address"]
STATUS_KEYS = ["status", "result", "outcome", "action", "event", "event_type", "message", "msg"]

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "gq", "ml", "cf", "work", "country", "gdn", "link", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly"}
BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "instagram",
          "dhl", "fedex", "coinbase", "binance", "whatsapp", "irs"]
CRED_PATH_RE = re.compile(r"login|signin|sign-in|verify|account|secure|update|confirm|password", re.I)

URGENCY = ["urgent", "immediately", "within 24 hours", "account will be suspended", "final notice",
           "verify your account", "unusual sign-in", "password expires", "action required",
           "limited time", "suspended"]
CREDENTIAL = ["enter your password", "login credentials", "verify your identity", "confirm your account",
              "update your payment", "bank details", "one-time password", "social security"]
ATTACH_RE = re.compile(r"[\w\-]+\.(exe|scr|js|vbs|bat|cmd|lnk|iso|img|docm|xlsm|zip|rar|html?)\b", re.I)
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".lnk", ".iso", ".img", ".docm", ".xlsm",
             ".zip", ".rar", ".html", ".htm"}
EXEC_TYPES = {"windows-executable", "elf-executable"}
MAGIC = [(b"%PDF", "pdf"), (b"PK\x03\x04", "zip-or-office"), (b"MZ", "windows-executable"),
         (b"\x7fELF", "elf-executable"), (b"\xd0\xcf\x11\xe0", "ole2-document")]

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

ACTIONS = {
    "Repeated failed logins": [
        "Rate-limit or block the source IP after confirming it is not a known VPN, NAT or legitimate user.",
        "Enforce MFA and review lockout thresholds for the targeted accounts."],
    "Possible password spraying": [
        "Check other accounts for failures from the same source and enforce MFA organisation-wide."],
    "Success after repeated failures": [
        "Treat the account as potentially compromised: reset the password, revoke sessions and tokens, and review actions taken after the login.",
        "Verify the login with the account owner through a known channel."],
    "Off-hours successful login": ["Confirm with the user whether the off-hours login was expected."],
    "High event volume from one source": ["Check whether automation or a service account explains the volume."],
    "Urgency language": ["Warn users about urgency-based lures and remind them to verify requests via official channels."],
    "Credential or sensitive data request": ["Do not enter credentials. Report the message and check for other recipients."],
    "Risky attachment reference": ["Do not open attachments from this message. Quarantine and search mail logs for the sender."],
    "Link text/destination mismatch": ["Block the destination domain after confirmation and remove the message from inboxes."],
    "Reply-To domain mismatch": ["Verify the sender out-of-band and check for lookalike domains."],
    "Brand impersonation in sender": ["Report the impersonation and block the sender domain after review."],
    "Authentication failure": ["Treat the sender as unverified and review SPF, DKIM and DMARC enforcement at the gateway."],
    "Suspicious URL": ["Do not visit the URL from production devices. Verify it via your secure web gateway or threat intel platform first."],
    "Known-malicious IP reputation": ["Block the IP after confirming it is not business-critical, and hunt for connections to it."],
}


# ---------- result helpers ----------

def _ok(tool, data, refs=None):
    return {"tool": tool, "status": "success", "data": data, "evidence_refs": refs or []}


def _err(tool, msg):
    return {"tool": tool, "status": "error", "error": msg, "data": None, "evidence_refs": []}


def make_finding(category, severity, indicator, description, refs, kind, confidence):
    """kind: 'observed' (literal evidence) | 'intel' (external source) | 'heuristic' (rule interpretation)."""
    return {"category": category, "severity": severity, "indicator": indicator,
            "description": description, "evidence_refs": list(refs)[:10], "kind": kind,
            "confidence": round(confidence, 2)}


def _refs(filename, evs):
    return [f"{filename}:L{e['line']}" for e in evs]


# ---------- log parsing ----------

def _ts_text(text):
    m = ISO_TS.search(text or "") or SYSLOG_TS.search(text or "")
    return m.group(0) if m else None


def _hour(ts):
    m = HOUR_RE.search(ts or "")
    return int(m.group(1)) if m else None


def _user(text):
    m = USER_RE.search(text)
    if not m:
        return None
    val = m.group(1)
    return None if IP_RE.fullmatch(val) else val


def _event(line, ts, user, ip, status, raw):
    return {"line": line, "timestamp": ts, "user": user, "ip": ip, "status": status, "raw": raw[:300]}


def _from_text(line, lineno):
    if not AUTH_CTX.search(line):
        return None
    if FAIL_RE.search(line):
        status = "failure"
    elif OK_RE.search(line):
        status = "success"
    else:
        return None
    ip = IP_RE.search(line)
    return _event(lineno, _ts_text(line), _user(line), ip.group(0) if ip else None, status, line)


def _from_record(rec, lineno):
    r = {str(k).strip().lower(): v for k, v in rec.items()}

    def field(keys):
        for k in keys:
            v = r.get(k)
            if v not in (None, ""):
                return str(v)
        return None

    blob = " ".join(str(r[k]) for k in STATUS_KEYS if r.get(k) not in (None, ""))
    if not blob:
        return None
    if FAIL_RE.search(blob):
        status = "failure"
    elif OK_RE.search(blob):
        status = "success"
    else:
        return None
    ip_m = IP_RE.search(field(IP_KEYS) or "")
    ts = field(TS_KEYS)
    ts = (_ts_text(ts) or ts[:40]) if ts else None
    return _event(lineno, ts, field(USER_KEYS), ip_m.group(0) if ip_m else None, status,
                  json.dumps(rec, default=str))


def parse_log(text, filename=""):
    """Returns (format, events). Supports JSON array, CSV, JSON-lines and plain syslog-style text."""
    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = data.get("events") or data.get("logs") or data.get("records") or [data]
            if isinstance(data, list):
                events = []
                for i, rec in enumerate(data):
                    if isinstance(rec, dict):
                        e = _from_record(rec, i + 1)
                        if e:
                            events.append(e)
                return "json", events
        except json.JSONDecodeError:
            pass

    first = stripped.split("\n", 1)[0]
    if filename.lower().endswith(".csv") or first.count(",") >= 2:
        try:
            rows = list(csv.DictReader(io.StringIO(stripped)))
            events = []
            for i, row in enumerate(rows):
                e = _from_record(row, i + 2)
                if e:
                    events.append(e)
            if events or filename.lower().endswith(".csv"):
                return "csv", events
        except csv.Error:
            pass

    events, fmt = [], "txt"
    for i, line in enumerate(stripped.splitlines()):
        e = None
        if line.lstrip().startswith("{"):
            try:
                obj = json.loads(line)
                e = _from_record(obj, i + 1) if isinstance(obj, dict) else None
                fmt = "jsonl"
            except json.JSONDecodeError:
                e = None
        else:
            e = _from_text(line, i + 1)
        if e:
            events.append(e)
    return fmt, events


def incident_timeline_generator(events):
    """Orders events chronologically (untimestamped events keep line order at the end)."""
    ordered = sorted(events, key=lambda e: (0, e["timestamp"]) if e.get("timestamp") else (1, e.get("line", 0)))
    return [{"step": i, "timestamp": e.get("timestamp") or "unknown",
             "event": f"{e.get('status')} | user={e.get('user') or '-'} | ip={e.get('ip') or '-'}",
             "ref": f"L{e.get('line')}"}
            for i, e in enumerate(ordered[:500], 1)]


def log_analyzer(text, filename="log", fail_threshold=5):
    tool = "log_analyzer"
    if not isinstance(text, str) or not text.strip():
        return _err(tool, "Empty log input")
    if len(text) > MAX_INPUT_CHARS:
        return _err(tool, "Log exceeds size limit")

    fmt, events = parse_log(text, filename)
    if not events:
        return _ok(tool, {"format": fmt, "events_parsed": 0, "findings": [], "timeline": [], "ips": [],
                          "users": [], "note": "No authentication-related events recognised."})

    by_ip = defaultdict(list)
    for e in events:
        if e["ip"]:
            by_ip[e["ip"]].append(e)

    findings = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e["status"] == "failure"]
        succs = [e for e in evs if e["status"] == "success"]
        users = {e["user"] for e in fails if e["user"]}

        if len(fails) >= fail_threshold:
            sev = "HIGH" if len(fails) >= 2 * fail_threshold else "MEDIUM"
            findings.append(make_finding("Repeated failed logins", sev, ip,
                            f"{len(fails)} failed authentication events from {ip}.",
                            _refs(filename, fails), "observed", 0.85))
            if len(users) >= 3:
                findings.append(make_finding("Possible password spraying", "HIGH", ip,
                                f"Failures against {len(users)} distinct accounts from {ip}; consistent with spraying.",
                                _refs(filename, fails), "heuristic", 0.6))

        for s in succs:
            prior_ip = [f for f in fails if f["line"] < s["line"]]
            if len(prior_ip) >= fail_threshold:
                targeted = [f for f in prior_ip if s["user"] and f["user"] == s["user"]]
                sev = "CRITICAL" if targeted else "HIGH"
                note = (f"; the account was targeted {len(targeted)} time(s) from this source" if targeted else "")
                findings.append(make_finding("Success after repeated failures", sev, ip,
                                f"Successful login for '{s['user'] or 'unknown'}' from {ip} after "
                                f"{len(prior_ip)} earlier failures from the same source{note}.",
                                _refs(filename, prior_ip[-5:] + [s]), "heuristic", 0.7))
                break

        if len(evs) >= 50:
            findings.append(make_finding("High event volume from one source", "MEDIUM", ip,
                            f"{len(evs)} authentication events from {ip}.",
                            _refs(filename, evs[:10]), "observed", 0.7))

    for s in events:
        h = _hour(s["timestamp"])
        if s["status"] == "success" and h is not None and 0 <= h < 5:
            findings.append(make_finding("Off-hours successful login", "LOW", s["ip"] or "unknown",
                            f"Successful login at {s['timestamp']} (00:00-05:00 in log time).",
                            _refs(filename, [s]), "heuristic", 0.4))
            break

    return _ok(tool, {
        "format": fmt,
        "events_parsed": len(events),
        "failures": sum(e["status"] == "failure" for e in events),
        "successes": sum(e["status"] == "success" for e in events),
        "ips": sorted(by_ip.keys()),
        "users": sorted({e["user"] for e in events if e["user"]}),
        "findings": findings,
        "timeline": incident_timeline_generator(events)[:300],
    }, _refs(filename, events[:50]))


# ---------- URL and IP indicators ----------

def url_indicator_analyzer(urls):
    """Parses URLs and flags structural risk. URLs are NEVER fetched."""
    tool = "url_indicator_analyzer"
    if not urls:
        return _err(tool, "No URLs provided")
    results = []
    for raw in list(urls)[:50]:
        raw = str(raw).strip()[:2048]
        u = urlparse(raw if "://" in raw else "http://" + raw)
        host = (u.hostname or "").lower()
        flags = []
        registrable = host
        if not host:
            flags.append("no hostname parsed")
        else:
            is_ip = bool(IP_RE.fullmatch(host))
            registrable = host if is_ip else ".".join(host.split(".")[-2:])
            if is_ip:
                flags.append("host is a raw IP address")
            if "xn--" in host:
                flags.append("punycode label (possible homograph)")
            if "@" in u.netloc:
                flags.append("'@' in authority section (masking)")
            if host.count(".") >= 4:
                flags.append("deeply nested subdomains")
            if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
                flags.append("higher-risk TLD")
            if host in SHORTENERS:
                flags.append("URL shortener hides destination")
            if u.scheme == "http":
                flags.append("unencrypted HTTP")
            if CRED_PATH_RE.search(u.path + "?" + u.query):
                flags.append("credential-themed path or query")
            for b in BRANDS:
                if b in host and not registrable.startswith(b + "."):
                    flags.append(f"brand '{b}' used outside its own domain")
                    break
        if len(raw) > 150:
            flags.append("unusually long URL")
        risk = "HIGH" if len(flags) >= 3 else "MEDIUM" if flags else "LOW"
        results.append({"url": raw[:300], "host": host, "registrable_domain": registrable,
                        "flags": flags, "risk": risk, "fetched": False})
    return _ok(tool, {"results": results, "note": "URLs were parsed, never fetched."},
               [f"url:{r['url'][:60]}" for r in results])


def _abuseipdb(ip):
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return {"source": "local heuristic only", "live": False,
                "note": "Set ABUSEIPDB_API_KEY for live reputation"}
    req = urllib.request.Request(ABUSE_URL.format(ip=ip), headers={"Key": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())["data"]
        return {"source": "AbuseIPDB", "live": True,
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"), "country": d.get("countryCode")}
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
        return {"source": "AbuseIPDB", "live": False, "error": str(e)[:120]}


def ip_indicator_analyzer(ips):
    tool = "ip_indicator_analyzer"
    if not ips:
        return _err(tool, "No IP addresses provided")
    results, lookups = [], 0
    for raw in list(ips)[:50]:
        try:
            ip = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            results.append({"input": str(raw)[:64], "valid": False, "risk": "INVALID"})
            continue
        entry = {"ip": str(ip), "valid": True, "version": ip.version}
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            entry.update(classification="internal/reserved", risk="LOW",
                         reputation={"source": "not applicable"})
        else:
            entry["classification"] = "public"
            if os.getenv("ABUSEIPDB_API_KEY") and lookups < 10:
                lookups += 1
                rep = _abuseipdb(str(ip))
            else:
                rep = _abuseipdb_placeholder()
            entry["reputation"] = rep
            score = rep.get("abuse_confidence_score") or 0
            if rep.get("live"):
                entry["risk"] = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
            else:
                entry["risk"] = "UNKNOWN"
        results.append(entry)
    return _ok(tool, {"results": results}, [f"ip:{r.get('ip', r.get('input'))}" for r in results])


def _abuseipdb_placeholder():
    return {"source": "local heuristic only", "live": False,
            "note": "Set ABUSEIPDB_API_KEY for live reputation (or lookup cap reached)"}


# ---------- phishing / email ----------

def phishing_email_analyzer(text, headers=""):
    """Inspects email text and headers. Does not visit links or open attachments."""
    tool = "phishing_email_analyzer"
    if not isinstance(text, str) or not text.strip():
        return _err(tool, "Empty email input")
    if len(text) > MAX_INPUT_CHARS:
        return _err(tool, "Input exceeds size limit")

    hdr = headers or (text.split("\n\n", 1)[0] if re.match(r"[A-Za-z-]+:\s", text) else "")
    body = text[len(hdr):] if hdr and text.startswith(hdr) else text
    low = body.lower()
    findings = []

    urg = [p for p in URGENCY if p in low]
    cred = [p for p in CREDENTIAL if p in low]
    if urg:
        findings.append(make_finding("Urgency language", "MEDIUM", "text",
                        "Urgency phrases: " + ", ".join(urg[:6]), ["body"], "observed", 0.6))
    if cred:
        findings.append(make_finding("Credential or sensitive data request", "HIGH", "text",
                        "Requests for sensitive data: " + ", ".join(cred[:6]), ["body"], "observed", 0.7))

    att = sorted({m.group(0).lower() for m in ATTACH_RE.finditer(body)
                  if "." + m.group(1).lower() in RISKY_EXT})
    if att:
        findings.append(make_finding("Risky attachment reference", "HIGH", ", ".join(att[:5]),
                        "References to executable or macro-capable files: " + ", ".join(att[:5]),
                        ["body"], "observed", 0.7))

    hrefs = []
    for href, label in re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", body, re.I | re.S):
        hrefs.append(href)
        label_txt = re.sub(r"<[^>]+>", "", label).strip()
        m = DOMAIN_RE.search(label_txt)
        href_host = (urlparse(href).hostname or "").lower()
        if m and href_host and m.group(1).lower() not in href_host:
            findings.append(make_finding("Link text/destination mismatch", "HIGH", href[:100],
                            f"Link displays '{label_txt[:60]}' but points to {href_host}.",
                            ["body"], "observed", 0.85))

    def dom(s):
        m = EMAIL_RE.search(s or "")
        return m.group(1).lower() if m else None

    frm = re.search(r"^From:\s*(.+)$", hdr, re.M | re.I)
    rep = re.search(r"^Reply-To:\s*(.+)$", hdr, re.M | re.I)
    from_val = frm.group(1).strip() if frm else ""
    from_dom = dom(from_val)
    display = from_val.split("<")[0].strip().strip('"').lower() if "<" in from_val else ""

    if rep and dom(rep.group(1)) and from_dom and dom(rep.group(1)) != from_dom:
        findings.append(make_finding("Reply-To domain mismatch", "MEDIUM",
                        f"{from_dom} vs {dom(rep.group(1))}",
                        f"From domain {from_dom} differs from Reply-To domain {dom(rep.group(1))}.",
                        ["headers"], "observed", 0.7))

    brand = next((b for b in BRANDS if b in display), None) if display else None
    from_reg = ".".join(from_dom.split(".")[-2:]) if from_dom else ""
    if brand and from_dom and not from_reg.startswith(brand + "."):
        findings.append(make_finding("Brand impersonation in sender", "HIGH", f"{brand} / {from_dom}",
                        f"Display name mentions '{brand}' but sender domain is {from_dom}.",
                        ["headers"], "heuristic", 0.7))

    for mech in ("spf", "dkim", "dmarc"):
        if re.search(mech + r"=fail", hdr, re.I):
            findings.append(make_finding("Authentication failure", "HIGH", mech.upper(),
                            f"{mech.upper()} reported fail in Authentication-Results.",
                            ["headers"], "observed", 0.8))

    urls_found = list(dict.fromkeys(URL_RE.findall(body) + hrefs))
    return _ok(tool, {
        "findings": findings,
        "urls_found": urls_found[:30],
        "header_ips": list(dict.fromkeys(IP_RE.findall(hdr))),
        "sender_domain": from_dom,
        "urgency_terms": urg,
        "credential_terms": cred,
        "not_executed": "No links were visited and no attachments were opened.",
    }, ["headers" if hdr else "body"])


# ---------- files ----------

def file_metadata_analyzer(path, original_name):
    tool = "file_metadata_analyzer"
    try:
        size = os.path.getsize(path)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            head = f.read(16)
            f.seek(0)
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        return _err(tool, f"Cannot read file: {e}")

    detected = next((t for sig, t in MAGIC if head.startswith(sig)), "text-or-unknown")
    ext = os.path.splitext(original_name)[1].lower()
    warnings = []
    blocked = detected in EXEC_TYPES
    if blocked:
        warnings.append("Executable signature detected. File was NOT executed and its content will not be analysed.")
    if ext == ".pdf" and detected != "pdf":
        warnings.append("Extension says PDF but the file signature does not match.")
    if ext in {".exe", ".scr", ".bat", ".vbs", ".js"}:
        warnings.append(f"Script or executable extension '{ext}' stored as evidence only.")

    meta = {}
    if detected == "pdf":
        try:
            import fitz  # PyMuPDF, optional
            doc = fitz.open(path)
            meta = {k: v for k, v in (doc.metadata or {}).items() if v}
            meta["page_count"] = doc.page_count
            doc.close()
        except ImportError:
            meta = {"note": "Install PyMuPDF to extract PDF metadata."}
        except Exception as e:  # malformed PDF
            meta = {"error": str(e)[:120]}

    return _ok(tool, {"original_name": original_name, "extension": ext, "size": size,
                      "sha256": h.hexdigest(), "detected_type": detected, "warnings": warnings,
                      "blocked": blocked, "metadata": meta},
               [f"sha256:{h.hexdigest()[:16]}"])


def extract_text(path, ext):
    """Reads evidence as text. PDFs need PyMuPDF; without it they yield no text."""
    if ext.lower() == ".pdf":
        try:
            import fitz
            doc = fitz.open(path)
            text = "\n".join(p.get_text() for p in doc)
            doc.close()
            return text[:MAX_INPUT_CHARS]
        except Exception:
            return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(MAX_INPUT_CHARS)


# ---------- correlation and risk ----------

def event_correlator(sources):
    """sources: {source_name: iterable of indicators}. Returns indicators seen in 2+ sources."""
    seen = defaultdict(set)
    for name, items in sources.items():
        for it in items or []:
            if it:
                seen[str(it).lower()].add(name)
    shared = [{"indicator": k, "sources": sorted(v)} for k, v in seen.items() if len(v) >= 2]
    shared.sort(key=lambda s: -len(s["sources"]))
    return _ok("event_correlator", {"shared_indicators": shared, "source_count": len(sources)})


def risk_assessment(findings, shared_count=0, sources_used=0):
    tool = "risk_assessment"
    raw = sum(SEV_POINTS.get(f["severity"], 0) * WEIGHT.get(f["kind"], 0.5) for f in findings)
    raw += 12 * shared_count
    score = int(min(100, round(raw)))
    category = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"

    confirmed = [f for f in findings if f["kind"] in ("observed", "intel")]
    if findings:
        confidence = min(0.95, 0.3 + 0.1 * len(confirmed) + 0.05 * min(sources_used, 4) + 0.05 * min(shared_count, 2))
    else:
        confidence = 0.4

    actions = []
    worst = {}
    for f in findings:
        worst[f["category"]] = min(worst.get(f["category"], 9), SEV_ORDER.get(f["severity"], 9))
    for cat in sorted(worst, key=lambda c: worst[c]):
        for a in ACTIONS.get(cat, []):
            if a not in actions:
                actions.append(a)
    if not actions:
        actions.append("No rule matched. Absence of matches is not proof of safety; provide more complete logs for review.")
    actions.append("Preserve original evidence and file hashes before any remediation.")

    rationale = (f"{len(findings)} finding(s): {len(confirmed)} observed or intel-backed, "
                 f"{len(findings) - len(confirmed)} heuristic. {shared_count} cross-source correlation(s).")
    return _ok(tool, {
        "score": score,
        "category": category,
        "confidence": round(confidence, 2),
        "rationale": rationale,
        "recommended_actions": actions,
        "disclaimer": "Score reflects rule matches and intelligence, not proof that an attack occurred.",
    })
