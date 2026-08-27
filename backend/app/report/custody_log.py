"""Append-only hash-chained chain-of-custody log.   OWNER: M4.

One JSON object per line in evidence/custody_log.jsonl.  Each entry stores the
hash of the previous entry, so altering or deleting any past entry breaks the
chain and verify_custody_chain() detects it.  That is the entire mechanism, and
it is genuinely the same primitive a blockchain uses for its ledger - minus the
distributed consensus we have no need for.

Say "hash chain in an append-only log", not "blockchain".  Describing it
accurately invites a question you win; overclaiming invites one you lose.

Entry shape (FROZEN - the /api/v1/custody-log endpoint returns these directly):
  {
    "entry_no": 17,
    "recorded_at": "2026-08-26T10:14:23Z",
    "analysis_id": "b7c1...",
    "evidence_sha256": "4d0a...",
    "report_id": "RPT-20260826-0017",
    "actor": "local-analyst",
    "meta": {"filename": "sample.eml", "byte_size": 12043},
    "previous_entry_hash": "1c8e...",   // null for entry 1
    "entry_hash": "9a77..."             // sha256 of this entry sans entry_hash
  }

IMPLEMENTATION NOTE - do not "simplify" this:
    We import the config MODULE and read config.CUSTODY_LOG_PATH inside each
    function, rather than doing `from ..core.config import CUSTODY_LOG_PATH` at
    import time.  Two reasons: the tests monkeypatch config.CUSTODY_LOG_PATH to
    a tmp_path, and DEMO_MODE/env overrides should be respected without a
    reimport.  A from-import would bind the value once and silently ignore both.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..core import config

IS_STUB = False   # implemented

log = logging.getLogger(__name__)

# Who is recorded as having performed the analysis.  Single-analyst tool for the
# MVP; multi-user attribution is Phase 4.
ACTOR = os.environ.get("CUSTODY_ACTOR", "local-analyst")

# FastAPI runs sync endpoints in a threadpool, so two analyses can land at the
# same moment.  Without this, both could read the same "last entry" and write
# two entries claiming the same predecessor, which would look like tampering.
_WRITE_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_path() -> Path:
    """Resolved at call time - see the implementation note in the docstring."""
    return Path(config.CUSTODY_LOG_PATH)


def _canonical(obj: dict) -> str:
    """Same canonicalisation as report_builder.canonical_evidence_hash().
    Deliberately duplicated rather than imported: this module must keep working
    even if report_builder is mid-edit, and four lines is a cheap price for
    that independence."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _entry_hash(entry: dict) -> str:
    """SHA-256 of the entry with entry_hash itself removed.

    Excluding "entry_hash" is not optional - at the time we compute it the field
    does not exist yet, and on verification it must be removed again or the
    recomputed digest can never match the stored one.
    """
    payload = {k: v for k, v in dict(entry).items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _read_raw() -> list[tuple[int, str]]:
    """[(line_number, text), ...] for non-blank lines.  Missing file -> []."""
    path = _log_path()
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as fh:
            return [(i, line.strip())
                    for i, line in enumerate(fh, start=1) if line.strip()]
    except OSError as exc:
        log.warning("custody log unreadable at %s: %s", path, exc)
        return []


# --------------------------------------------------------------------------- #
# append
# --------------------------------------------------------------------------- #
def append_custody_entry(analysis_id: str, evidence_sha256: str,
                         meta: dict) -> tuple[int, str | None]:
    """MAIN ENTRY POINT.  -> (entry_no, previous_entry_hash)

    Returns (0, None) on any failure and never raises.  pipeline.py turns that
    into a `warnings` entry and still returns the analysis - a failed custody
    write must not lose the analysis the user just waited for.

    Append-only "a" mode gives us the crash-safety we need for free: a partial
    final line cannot corrupt any earlier entry, and verify_custody_chain()
    reports the partial line as a break rather than crashing on it.
    """
    try:
        with _WRITE_LOCK:
            entries = read_custody_log()
            last = entries[-1] if entries else None
            entry_no = int(last.get("entry_no", len(entries))) + 1 if last else 1
            previous_entry_hash = last.get("entry_hash") if last else None

            entry = {
                "entry_no": entry_no,
                "recorded_at": _utc_now(),
                "analysis_id": analysis_id,
                "evidence_sha256": evidence_sha256,
                "report_id": f"RPT-{datetime.now(timezone.utc):%Y%m%d}-{entry_no:04d}",
                "actor": ACTOR,
                "meta": meta if isinstance(meta, dict) else {},
                "previous_entry_hash": previous_entry_hash,
            }
            entry["entry_hash"] = _entry_hash(entry)

            path = _log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())   # survive a crash mid-demo

            return entry_no, previous_entry_hash

    except Exception as exc:                       # noqa: BLE001 - never propagate
        log.warning("custody log append failed: %s", exc)
        return 0, None


# --------------------------------------------------------------------------- #
# read
# --------------------------------------------------------------------------- #
def read_custody_log() -> list[dict]:
    """All well-formed entries, oldest first.  -> GET /api/v1/custody-log

    Unparseable lines are SKIPPED here rather than raising, so a corrupt log can
    still be displayed.  Detecting that corruption is verify_custody_chain()'s
    job, and it re-reads the raw lines itself precisely so that this skipping
    cannot hide a break.
    """
    entries: list[dict] = []
    for lineno, text in _read_raw():
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                entries.append(obj)
            else:
                log.warning("custody log line %d is not an object", lineno)
        except json.JSONDecodeError:
            log.warning("custody log line %d is not valid JSON, skipping", lineno)
    return entries


# --------------------------------------------------------------------------- #
# verify - this is the demo
# --------------------------------------------------------------------------- #
def verify_custody_chain() -> dict:
    """Recompute the chain and report whether it is intact.

    -> {"entries": int, "intact": bool, "broken_at": int | None, "detail": str}

    Three independent checks per entry, any of which is enough to prove
    tampering:
      1. the stored entry_hash matches a recomputation of the entry's contents
      2. previous_entry_hash matches the actual previous entry's entry_hash
      3. entry_no runs 1..N with no gaps (catches a deleted line)

    Demo move worth 30 seconds of stage time: run this, show intact: true,
    hand-edit one character in the JSONL in front of the judges, run it again,
    show it now names the exact entry where the chain broke.  That single
    interaction communicates tamper-evidence better than any slide.
    """
    raw = _read_raw()
    if not raw:
        return {"entries": 0, "intact": True, "broken_at": None,
                "detail": "Custody log is empty. No analyses have been recorded yet."}

    entries: list[dict] = []
    for lineno, text in raw:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return {
                "entries": len(entries), "intact": False, "broken_at": lineno,
                "detail": (f"Line {lineno} is not valid JSON. The log has been "
                           f"edited or truncated after it was written."),
            }
        if not isinstance(obj, dict):
            return {"entries": len(entries), "intact": False, "broken_at": lineno,
                    "detail": f"Line {lineno} is not a custody entry object."}
        entries.append(obj)

    previous_hash: str | None = None
    for position, entry in enumerate(entries, start=1):
        entry_no = entry.get("entry_no")
        where = entry_no if isinstance(entry_no, int) else position

        if entry_no != position:
            return {
                "entries": len(entries), "intact": False, "broken_at": where,
                "detail": (f"Entry at position {position} is numbered {entry_no!r}. "
                           f"An entry has been deleted, reordered, or renumbered."),
            }

        stored = entry.get("entry_hash")
        recomputed = _entry_hash(entry)
        if stored != recomputed:
            return {
                "entries": len(entries), "intact": False, "broken_at": where,
                "detail": (f"Entry {where} does not match its own hash. Its "
                           f"contents were altered after it was recorded "
                           f"(stored {str(stored)[:12]}…, recomputed "
                           f"{recomputed[:12]}…)."),
            }

        if entry.get("previous_entry_hash") != previous_hash:
            return {
                "entries": len(entries), "intact": False, "broken_at": where,
                "detail": (f"Entry {where} does not link to the entry before it. "
                           f"The chain was broken at or before this point."),
            }

        previous_hash = stored

    return {
        "entries": len(entries),
        "intact": True,
        "broken_at": None,
        "detail": (f"All {len(entries)} entries verified: each entry matches its "
                   f"own hash and correctly references the entry before it."),
    }