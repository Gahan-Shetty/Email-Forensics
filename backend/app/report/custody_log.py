"""Append-only hash-chained chain-of-custody log.   OWNER: M4.

One JSON object per line in evidence/custody_log.jsonl.  Each entry stores the
hash of the previous entry, so altering or deleting any past entry breaks the
chain and verify_custody_chain() detects it.  That is the entire mechanism, and
it is genuinely the same primitive a blockchain uses for its ledger - minus the
distributed consensus we have no need for.

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
"""
from __future__ import annotations

IS_STUB = True   # <-- M4: set False when append_custody_entry is implemented


def _entry_hash(entry: dict) -> str:
    """sha256 of the entry with entry_hash itself removed, canonical JSON.

    TODO(M4): identical technique to canonical_evidence_hash - sort_keys=True,
    compact separators.  Must exclude the "entry_hash" key or you are hashing
    a field that does not exist yet.
    """
    return ""


def append_custody_entry(analysis_id: str, evidence_sha256: str,
                         meta: dict) -> tuple[int, str | None]:
    """MAIN ENTRY POINT.  -> (entry_no, previous_entry_hash)

    TODO(M4):
      1. read the last line of CUSTODY_LOG_PATH (read the whole file for MVP -
         it will have tens of entries, not millions)
      2. entry_no = last["entry_no"] + 1, or 1 if the file is empty/missing
      3. previous_entry_hash = last["entry_hash"], or None for entry 1
      4. build the entry, compute entry_hash = _entry_hash(entry), set it
      5. append one line with "a" mode + json.dumps + "\n", then flush
      6. return (entry_no, previous_entry_hash)

    Must be crash-safe enough that a half-written line cannot corrupt earlier
    entries - append-only mode gives you that for free.  Create the parent
    directory if missing (config already does this at import, but be defensive).

    Never raise into the request path.  If the log write fails, log a warning,
    return (0, None), and let main.py add a `warnings` entry.  A failed custody
    write must not lose the analysis the user just waited for.
    """
    return 0, None


def read_custody_log() -> list[dict]:
    """All entries, oldest first.  -> GET /api/v1/custody-log

    TODO(M4): read the file line by line, json.loads each, SKIP unparseable
    lines rather than raising, return [].  Missing file -> [].
    """
    return []


def verify_custody_chain() -> dict:
    """Recompute the chain and report whether it is intact.

    TODO(M4): -> {"entries": n, "intact": bool, "broken_at": entry_no | None,
                  "detail": str}
    For each entry i>0: entry[i]["previous_entry_hash"] must equal
    entry[i-1]["entry_hash"], AND recomputing _entry_hash(entry[i]) must match
    its stored entry_hash.

    Demo move worth 30 seconds of stage time: run this, show "intact: true",
    hand-edit one character in the JSONL in front of the judges, run it again,
    show it now reports the exact entry number where the chain broke.  That
    single interaction communicates tamper-evidence better than any slide.
    """
    return {"entries": 0, "intact": True, "broken_at": None, "detail": "stub"}
