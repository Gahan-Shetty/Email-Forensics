"""Forensic report assembly + evidence hashing.   OWNER: M4.

Produces -> response["report"]  and the JSON served at /api/v1/report/{id}.json

The hash is the point of this module.  "Chain of custody" here means: we can
prove the evidence we exported has not been altered since export.  We do that
with a canonical serialisation + SHA-256 + an append-only hash-chained log.
No blockchain, and you should say that plainly if asked - a hash chain in an
append-only log is the actual primitive that matters, and claiming
"blockchain" for a local JSONL file invites a question you will lose.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

IS_STUB = True   # <-- M4: set False when build_report_payload is implemented

# Fields excluded from the hash because they change between runs for reasons
# that are not evidence.  Hashing these would make verification always fail.
HASH_EXCLUDED_TOP_LEVEL = {"timings_ms", "report", "module_status"}


def canonical_evidence_hash(analysis: dict) -> str:
    """SHA-256 over a canonical JSON serialisation of the evidence.

    TODO(M4):
      payload = {k: v for k, v in analysis.items() if k not in HASH_EXCLUDED_TOP_LEVEL}
      blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, default=str)
      return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    sort_keys=True is load-bearing: dict ordering must not change the hash, or
    the same evidence hashes differently on different runs and the whole
    tamper-evidence claim collapses.  Write a test that hashes the same analysis
    twice with shuffled key order and asserts the hashes match.
    """
    payload = {k: v for k, v in analysis.items() if k not in HASH_EXCLUDED_TOP_LEVEL}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_report_payload(analysis: dict) -> dict:
    """The report document.  Saved as JSON, and the input to render_pdf().

    TODO(M4) - structure it like a real forensic exhibit, in this order:
      1. case header      report_id, generated_at (UTC Z), analysis_id,
                          tool name + version, input sha256 + filename/size
      2. summary          risk score + band + verdict, and origin["statement"]
                          VERBATIM.  Do not reword it, do not drop the
                          confidence sentence, do not "tidy up" the caveat.
      3. sender identity  From / Reply-To / Return-Path / Message-ID, plus M1's
                          anomaly list
      4. authentication   SPF / DKIM / DMARC results with their raw header text
                          and who verified them (auth["verified_by"]).  Flag
                          self_asserted_only loudly if set.
      5. routing          the full received_chain as an ordered table:
                          hop / timestamp / from_host / from_ip / by_host / TLS
      6. origin analysis  selected IP, geo, infrastructure_type, confidence,
                          and EVERY confidence_reason as a bullet
      7. limitations      fixed boilerplate - see LIMITATIONS_TEXT below.
                          This section is not padding; it is what makes the
                          document defensible.
      8. integrity        evidence_sha256, custody_log_entry, previous_entry_hash

    report_id format: RPT-YYYYMMDD-NNNN where NNNN is the custody log entry
    number zero-padded.  Sortable, human-readable, matches how real case
    references look.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "case_header": {"report_id": "RPT-STUB-0000", "generated_at": now},
        "summary": {}, "sender_identity": {}, "authentication": {},
        "routing": [], "origin_analysis": {},
        "limitations": LIMITATIONS_TEXT,
        "integrity": {"evidence_sha256": canonical_evidence_hash(analysis)},
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
