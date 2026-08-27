"""Forensic report assembly + evidence hashing.   OWNER: M4.

Produces -> response["report"]  and the JSON served at /api/v1/report/{id}.json

The hash is the point of this module.  "Chain of custody" here means: we can
prove the evidence we exported has not been altered since export.  We do that
with a canonical serialisation + SHA-256 + an append-only hash-chained log.
No blockchain, and you should say that plainly if asked - a hash chain in an
append-only log is the actual primitive that matters, and claiming
"blockchain" for a local JSONL file invites a question you will lose.

Design notes for whoever reads this later:

  * Every accessor in here is None-tolerant.  The report must render for
    samples/06_minimal_no_headers.eml, which has almost no data, and it must
    render while other members' modules are still stubs.  A report generator
    that throws KeyError on a sparse email is useless in the field.
  * This module imports NOTHING from parsing/ or intel/.  It reads the analysis
    dict defined in API_CONTRACT.md section 3 and nothing else.  That is what
    lets M4 finish before anyone else does.
  * The output dict of build_report_payload() is consumed by pdf_renderer.py.
    Both files are M4-owned, so that shape is ours to change - but change it in
    both files in the same commit.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

IS_STUB = False   # implemented

TOOL_NAME = "SIH26106 Email Forensic Analyzer"
TOOL_VERSION = "1.0"
REPORT_SCHEMA = "forensic-report/1.0"

# Fields excluded from the hash because they change between runs for reasons
# that are not evidence.  Hashing these would make verification always fail.
#
#   timings_ms     - wall-clock timings, different every run
#   report         - contains the hash itself; hashing it is circular
#   module_status  - build progress of OUR tool, not a property of the email
#   warnings       - our tool's own diagnostics.  ALSO: pipeline.py appends to
#                    the warnings list AFTER it calls canonical_evidence_hash(),
#                    so if warnings were hashed, the stored hash would not match
#                    a later recomputation at /report/{id}.json.  Excluding it
#                    makes the hash reproducible, which is the whole point.
HASH_EXCLUDED_TOP_LEVEL = {"timings_ms", "report", "module_status", "warnings"}

# Section order, shared with pdf_renderer.py so the PDF and the JSON agree.
SECTION_ORDER = [
    ("case_header", "1. Case header"),
    ("summary", "2. Summary of findings"),
    ("sender_identity", "3. Sender identity"),
    ("authentication", "4. Authentication results"),
    ("routing", "5. Delivery routing chain"),
    ("origin_analysis", "6. Origin analysis"),
    ("limitations", "7. Limitations of this analysis"),
    ("integrity", "8. Evidence integrity"),
]

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


# --------------------------------------------------------------------------- #
# small None-tolerant helpers
# --------------------------------------------------------------------------- #
def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _d(value) -> dict:
    """Coerce to dict.  Any block in the contract may be null while a module is
    a stub, so never index into one of these directly."""
    return value if isinstance(value, dict) else {}


def _l(value) -> list:
    return value if isinstance(value, list) else []


def _s(value, default: str = "—") -> str:
    """Display string.  Empty and None both become the em-dash placeholder, so
    the report never shows a bare 'None' to a reader."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _mailbox(mb) -> dict:
    """Contract Mailbox -> report-ready dict with a pre-formatted display line."""
    mb = _d(mb)
    name, addr, domain = mb.get("display_name"), mb.get("address"), mb.get("domain")
    if name and addr:
        display = f"{name} <{addr}>"
    else:
        display = _s(addr)
    return {
        "display_name": name,
        "address": addr,
        "domain": domain,
        "display": display,
    }


def _location_line(geo: dict) -> str:
    """City, Region, Country from whatever subset is present.

    Deliberately NOT importing M3's format_location(): that would couple this
    module to intel/confidence.py, and while M3 is still stubbed it returns an
    empty string.  Duplicating four lines is cheaper than the coupling.
    """
    geo = _d(geo)
    parts = [geo.get("city"), geo.get("region"), geo.get("country")]
    joined = ", ".join(p for p in parts if p)
    return joined or "Location not determined"


# --------------------------------------------------------------------------- #
# the hash - read the comments before touching any argument
# --------------------------------------------------------------------------- #
def canonical_evidence_hash(analysis: dict) -> str:
    """SHA-256 over a canonical JSON serialisation of the evidence.

    Every argument to json.dumps here is load-bearing:

      sort_keys=True        dict ordering must not change the hash, or the same
                            evidence hashes differently on different runs and
                            the tamper-evidence claim collapses.
      separators=(",",":")  no incidental whitespace in the hashed bytes.
      ensure_ascii=True     a non-ASCII subject line must hash identically on
                            every machine regardless of locale or terminal.
      default=str           never raise mid-hash on an unexpected type (a stray
                            datetime from a teammate's module, for example).
    """
    payload = {k: v for k, v in _d(analysis).items()
               if k not in HASH_EXCLUDED_TOP_LEVEL}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# sections 1-8
# --------------------------------------------------------------------------- #
def _case_header(analysis: dict) -> dict:
    """Section 1.  report_id comes from the pipeline if it already ran the
    custody append; the 0000 suffix means 'this analysis was never logged'."""
    inp = _d(analysis.get("input"))
    existing = _d(analysis.get("report"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return {
        "report_id": existing.get("report_id") or f"RPT-{stamp}-0000",
        "generated_at": _utc_now(),
        "analysis_id": analysis.get("analysis_id"),
        "analyzed_at": analysis.get("analyzed_at"),
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "schema_version": analysis.get("schema_version"),
        "input": {
            "source": inp.get("source"),
            "filename": inp.get("filename"),
            "byte_size": inp.get("byte_size", 0),
            "sha256": inp.get("sha256", ""),
        },
    }


def _summary(analysis: dict) -> dict:
    """Section 2.  origin["statement"] is reproduced VERBATIM - see
    API_CONTRACT.md section 6.  Do not reword it, do not drop the confidence
    sentence, do not 'tidy up' the caveat."""
    risk = _d(analysis.get("risk"))
    origin = _d(analysis.get("origin"))
    signals = _l(risk.get("signals"))
    triggered = [
        {
            "code": s.get("code"),
            "label": s.get("label"),
            "points": s.get("points", 0),
            "evidence": s.get("evidence"),
        }
        for s in signals if _d(s).get("triggered")
    ]
    score = risk.get("score", 0)
    band = _s(risk.get("band"), "unknown")
    verdict = _s(risk.get("verdict"), "inconclusive")
    return {
        "risk_score": score,
        "risk_band": band,
        "verdict": verdict,
        "headline": f"Risk {score}/100 ({band}) — assessed as {verdict.replace('_', ' ')}.",
        "confidence": _s(origin.get("confidence"), "low"),
        # verbatim, and never empty - the contract guarantees a statement
        "origin_statement": origin.get("statement") or "",
        "signals_triggered": triggered,
        "signals_triggered_count": len(triggered),
        "signals_evaluated_count": len(signals),
    }


def _sender_identity(analysis: dict) -> dict:
    """Section 3.  Anomalies sorted worst-first so a reader sees the important
    ones without reading the whole list."""
    h = _d(analysis.get("headers"))
    anomalies = sorted(
        (
            {
                "code": _d(a).get("code"),
                "severity": _d(a).get("severity", "info"),
                "detail": _d(a).get("detail"),
            }
            for a in _l(h.get("anomalies"))
        ),
        key=lambda a: (_SEVERITY_RANK.get(a["severity"], 9), str(a["code"])),
    )
    return {
        "from": _mailbox(h.get("from")),
        "reply_to": _mailbox(h.get("reply_to")) if h.get("reply_to") else None,
        "return_path": _mailbox(h.get("return_path")) if h.get("return_path") else None,
        "to": [_mailbox(m) for m in _l(h.get("to"))],
        "cc": [_mailbox(m) for m in _l(h.get("cc"))],
        "subject": h.get("subject"),
        "message_id": h.get("message_id"),
        "message_id_domain": h.get("message_id_domain"),
        "date": h.get("date"),
        "date_raw": h.get("date_raw"),
        "x_mailer": h.get("x_mailer"),
        "raw_header_count": h.get("raw_header_count", 0),
        "missing_headers": _l(h.get("missing_headers")),
        "anomalies": anomalies,
    }


def _authentication(analysis: dict) -> dict:
    """Section 4.  self_asserted_only is flagged loudly: it means the sender
    wrote its own Authentication-Results header and no trusted receiver
    corroborated it, so the passes in this section are worth nothing."""
    auth = _d(analysis.get("authentication"))
    mechanisms = []
    for name in ("spf", "dkim", "dmarc", "arc"):
        m = _d(auth.get(name))
        mechanisms.append({
            "name": name.upper(),
            "result": _s(m.get("result"), "none"),
            "domain": m.get("domain"),
            "selector": m.get("selector"),
            "policy": m.get("policy"),
            "raw": m.get("raw"),
            "source": m.get("source"),
        })
    self_asserted = bool(auth.get("self_asserted_only"))
    return {
        "verified_by": auth.get("verified_by"),
        "self_asserted_only": self_asserted,
        "self_asserted_warning": (
            "WARNING: no trusted receiving provider recorded an authentication "
            "result for this message. The results below were asserted by the "
            "sending side and carry no evidentiary weight."
        ) if self_asserted else None,
        "mechanisms": mechanisms,
        "alignment": _d(auth.get("alignment")),
        "failures": [m["name"] for m in mechanisms
                     if m["result"] in {"fail", "softfail", "permerror"}],
    }


def _routing(analysis: dict) -> dict:
    """Section 5.  hop 1 is closest to the sender - the chain was already
    reversed by M1, we present it in the order we are given."""
    hops = []
    for hop in _l(analysis.get("received_chain")):
        hop = _d(hop)
        hops.append({
            "hop": hop.get("hop_index"),
            "timestamp": hop.get("timestamp"),
            "timestamp_raw": hop.get("timestamp_raw"),
            "from_host": hop.get("from_host"),
            "from_ip": hop.get("from_ip"),
            "by_host": hop.get("by_host"),
            "protocol": hop.get("protocol"),
            "tls": bool(hop.get("tls")),
            "is_private_ip": bool(hop.get("is_private_ip")),
            "parse_ok": bool(hop.get("parse_ok", True)),
            "raw": hop.get("raw"),
        })
    integrity = _d(analysis.get("chain_integrity"))
    return {
        "hop_count": integrity.get("hop_count", len(hops)),
        "note": ("Hops are listed sender-first: hop 1 is the earliest recorded "
                 "handoff, closest to the originating system."),
        "hops": hops,
        "integrity": {
            "timestamps_monotonic": integrity.get("timestamps_monotonic", True),
            "backward_time_jumps": integrity.get("backward_time_jumps", 0),
            "largest_gap_seconds": integrity.get("largest_gap_seconds", 0),
            "gaps_suspected": bool(integrity.get("gaps_suspected")),
            "malformed_hops": integrity.get("malformed_hops", 0),
            "notes": _l(integrity.get("notes")),
        },
    }


def _origin_analysis(analysis: dict) -> dict:
    """Section 6.  EVERY confidence_reason is printed - they are the reason the
    confidence label is credible.  Never truncate this list.

    The ranked candidate list is included in full, excluded entries and all:
    showing what we rejected and why is more persuasive than showing only the
    winner, and it is the part that demonstrates we did not simply grab the
    first IP in the headers.
    """
    origin = _d(analysis.get("origin"))
    geo = _d(origin.get("geo"))
    candidates = []
    for i, c in enumerate(_l(analysis.get("ip_candidates")), start=1):
        c = _d(c)
        candidates.append({
            "rank": i,
            "ip": c.get("ip"),
            "hop": c.get("hop_index"),
            "trust_tier": c.get("trust_tier"),
            "trust_score": c.get("trust_score", 0.0),
            "observed_by": c.get("observed_by"),
            "observed_by_is_trusted_receiver": bool(c.get("observed_by_is_trusted_receiver")),
            "excluded": bool(c.get("excluded")),
            "exclusion_reason": c.get("exclusion_reason"),
            "reasons": _l(c.get("reasons")),
        })
    return {
        "selected_ip": origin.get("selected_ip"),
        "selected_from_hop": origin.get("selected_from_hop"),
        "location": _location_line(geo),
        "geo": {
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "region": geo.get("region"),
            "city": geo.get("city"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "isp": geo.get("isp"),
            "org": geo.get("org"),
            "asn": geo.get("asn"),
            "is_datacenter": bool(geo.get("is_datacenter")),
            "is_proxy": bool(geo.get("is_proxy")),
            "is_mobile": bool(geo.get("is_mobile")),
            "lookup_source": geo.get("lookup_source", "unavailable"),
        },
        "infrastructure_type": _s(origin.get("infrastructure_type"), "unknown"),
        "confidence": _s(origin.get("confidence"), "low"),
        "confidence_reasons": _l(origin.get("confidence_reasons")),
        "statement": origin.get("statement") or "",
        "candidates": candidates,
        "candidates_excluded_count": sum(1 for c in candidates if c["excluded"]),
    }


def _integrity(analysis: dict, evidence_hash: str) -> dict:
    """Section 8.  Explains the mechanism in the document itself, so the report
    is self-describing to someone who did not watch the demo."""
    existing = _d(analysis.get("report"))
    entry = existing.get("custody_log_entry")
    return {
        "evidence_sha256": evidence_hash,
        "hash_algorithm": "SHA-256",
        "canonicalisation": ("RFC 8785-style canonical JSON: keys sorted, "
                             "compact separators, ASCII-escaped"),
        "excluded_fields": sorted(HASH_EXCLUDED_TOP_LEVEL),
        "custody_log_entry": entry,
        "previous_entry_hash": existing.get("previous_entry_hash"),
        "statement": (
            f"The analysis evidence above hashes to the SHA-256 digest shown. "
            f"That digest is recorded as entry {entry} of an append-only "
            f"chain-of-custody log in which each entry embeds the hash of the "
            f"entry before it, so any later alteration to this or any earlier "
            f"record is detectable."
            if entry else
            "This analysis was not written to the chain-of-custody log, so the "
            "digest above is not yet anchored to a custody record."
        ),
    }


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def build_report_payload(analysis: dict) -> dict:
    """The report document.  Saved as JSON, and the input to render_pdf().

    Eight sections in the order a real forensic exhibit reads.  Called by
    main.py at GET /api/v1/report/{analysis_id}.json - it must therefore be
    pure and side-effect free: no file writes, no custody appends, no network.
    Calling it twice on the same analysis must produce the same evidence hash.
    """
    analysis = _d(analysis)
    evidence_hash = canonical_evidence_hash(analysis)
    return {
        "schema": REPORT_SCHEMA,
        "case_header": _case_header(analysis),
        "summary": _summary(analysis),
        "sender_identity": _sender_identity(analysis),
        "authentication": _authentication(analysis),
        "routing": _routing(analysis),
        "origin_analysis": _origin_analysis(analysis),
        "limitations": list(LIMITATIONS_TEXT),
        "integrity": _integrity(analysis, evidence_hash),
    }


LIMITATIONS_TEXT = [
    "Geolocation reflects the visible email-delivery infrastructure recorded in "
    "this message's headers. It is not a verified physical location of the sender.",
    "Where a VPN, proxy, Tor exit node, cloud host, or webmail provider is "
    "involved, the observed address identifies that intermediary infrastructure "
    "and not the originating device or person.",
    "Authentication results are as recorded by the receiving provider at the "
    "time of delivery. Where no trusted receiver recorded a result, any "
    "authentication claim present in the message is self-asserted by the sender "
    "and carries no evidentiary weight.",
    "Attribution to an identified person requires lawful access to records held "
    "by the relevant email provider, ISP, hosting provider, VPN operator, or "
    "domain registrar. This report is intended to support such a request, not "
    "to substitute for it.",
    "Header fields not recorded by a trusted intermediary can be forged by the "
    "sender and are reported as observed, not as verified.",
]