#!/usr/bin/env python3
"""Structural contract check.   OWNER: M6.

Runs the pipeline over every file in samples/ and compares the SHAPE of each
response against fixtures/sample_response.json - key by key, all the way down.
If a module's return shape drifts from the contract, this fails here instead of
failing silently in the UI three hours later.

Stdlib only, on purpose: it runs before `pip install`, on any machine, offline.
It is a shape check, not a correctness check - `pytest backend/tests` is still
the real gate.

    python scripts/verify_contract.py
    python scripts/verify_contract.py --verbose

Exit code 0 = shape conforms.  Anything else = read the output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app import pipeline  # noqa: E402
from backend.app.core.config import SCHEMA_VERSION  # noqa: E402
from backend.app.intel import confidence as m3_confidence  # noqa: E402
from backend.app.intel import risk_score as m3_risk  # noqa: E402

FIXTURE = ROOT / "fixtures" / "sample_response.json"
SAMPLES = ROOT / "samples"

# Object-valued paths the contract declares Optional (see schemas.py).  Anywhere
# else, a null where the contract promises an object is a bug: the frontend reads
# these blocks without guarding, so a surprise null is a TypeError in the UI.
# Scalar fields are nullable by default and handled in compare().
NULLABLE_PATHS = {
    "headers.reply_to",     # Mailbox | None  - most mail has no Reply-To
    "headers.return_path",  # Mailbox | None  - absent on pasted header blocks
    "report",               # ReportMeta | None - null until M4 is live
}

CONFIDENCE = {"high", "medium", "low"}
BANDS = {"low", "medium", "high", "critical"}
VERDICTS = {"likely_legitimate", "inconclusive", "suspicious", "likely_phishing"}
TIERS = {"provider_observed", "transit_relay", "client_asserted", "unverifiable"}

failures: list[str] = []
notes: list[str] = []


def fail(where: str, msg: str) -> None:
    failures.append(f"{where}: {msg}")


def shape(value):
    """Reduce a JSON value to a comparable type signature."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def compare(expected, actual, path: str, where: str) -> None:
    """Expected keys must all exist in actual.  Extra keys in actual are an error
    too - they mean someone added a field without updating the contract."""
    if isinstance(expected, dict):
        if actual == "null":
            if path in NULLABLE_PATHS:
                notes.append(f"{where}: {path} is null (contract allows it)")
                return
            fail(where, f"{path or 'root'} is null but the contract promises an "
                        f"object - the frontend reads it unguarded")
            return
        if not isinstance(actual, dict):
            fail(where, f"{path or 'root'} should be an object, got {actual!r}")
            return
        for key in expected:
            sub = f"{path}.{key}" if path else key
            if key not in actual:
                fail(where, f"missing key {sub}")
            else:
                compare(expected[key], actual[key], sub, where)
        for key in actual:
            if key not in expected:
                fail(where, f"undocumented extra key {path}.{key} - "
                            f"update API_CONTRACT.md and schemas.py")
        return

    if isinstance(expected, list):
        if not isinstance(actual, list):
            fail(where, f"{path} should be an array, got {actual!r}")
            return
        if expected and actual:
            compare(expected[0], actual[0], f"{path}[0]", where)
        return

    if expected != actual and "null" not in (expected, actual):
        fail(where, f"{path} type is {actual}, contract says {expected}")


def check_invariants(r: dict, where: str) -> None:
    """The hard rules from API_CONTRACT.md that must hold for EVERY response,
    stub or live.  These are the ones that would make the product dishonest."""
    if r.get("schema_version") != SCHEMA_VERSION:
        fail(where, f"schema_version {r.get('schema_version')!r} != {SCHEMA_VERSION!r}")

    for key in ("analysis_id", "analyzed_at"):
        if not r.get(key):
            fail(where, f"{key} is empty")

    origin = r.get("origin")
    if origin is None:
        fail(where, "origin block is null - contract requires an origin object "
                    "with confidence 'low' even when no IP is recoverable")
    else:
        conf = origin.get("confidence")
        if conf not in CONFIDENCE:
            fail(where, f"origin.confidence {conf!r} not in {sorted(CONFIDENCE)}")
        stmt = (origin.get("statement") or "").strip()
        if not stmt:
            fail(where, "origin.statement is empty - the report has no wording to print")
        elif conf and conf not in stmt.lower():
            fail(where, f"origin.statement does not carry its own confidence "
                        f"word ({conf!r}) - required by contract §6")
        if not origin.get("confidence_reasons"):
            fail(where, "origin.confidence_reasons is empty - every confidence "
                        "level must be explainable")

    risk = r.get("risk") or {}
    if risk.get("band") not in BANDS:
        fail(where, f"risk.band {risk.get('band')!r} not in {sorted(BANDS)}")
    if risk.get("verdict") not in VERDICTS:
        fail(where, f"risk.verdict {risk.get('verdict')!r} not in {sorted(VERDICTS)}")
    score = risk.get("score")
    if not isinstance(score, int) or not 0 <= score <= 100:
        fail(where, f"risk.score {score!r} is not an int in 0..100")
    signals = risk.get("signals") or []
    if len(signals) != len(m3_risk.SIGNAL_DEFS):
        fail(where, f"risk.signals has {len(signals)} entries, expected "
                    f"{len(m3_risk.SIGNAL_DEFS)} - all signals must always be "
                    f"listed, triggered or not, so the UI can show what was checked")
    expected_codes = [c for c, _l, _p in m3_risk.SIGNAL_DEFS]
    if [s.get("code") for s in signals] != expected_codes:
        fail(where, "risk.signals codes/order differ from SIGNAL_DEFS")

    for i, hop in enumerate(r.get("map_hops") or []):
        if hop.get("confidence") not in CONFIDENCE:
            fail(where, f"map_hops[{i}] has no valid confidence - an unlabelled "
                        f"pin on the map is exactly the overclaim we must not make")
        for coord in ("lat", "lon"):
            v = hop.get(coord)
            if not isinstance(v, (int, float)):
                fail(where, f"map_hops[{i}].{coord} is not numeric ({v!r})")

    cands = r.get("ip_candidates") or []
    for i, c in enumerate(cands):
        if c.get("trust_tier") not in TIERS:
            fail(where, f"ip_candidates[{i}].trust_tier {c.get('trust_tier')!r} invalid")
        ts = c.get("trust_score")
        if not isinstance(ts, (int, float)) or not 0.0 <= ts <= 1.0:
            fail(where, f"ip_candidates[{i}].trust_score {ts!r} outside 0.0..1.0")
        if c.get("excluded") and not c.get("exclusion_reason"):
            fail(where, f"ip_candidates[{i}] excluded with no exclusion_reason - "
                        f"the UI must be able to say why")
    keys = [(c.get("excluded", False), -float(c.get("trust_score") or 0),
             c.get("hop_index") or 0) for c in cands]
    if keys != sorted(keys):
        fail(where, "ip_candidates not sorted (excluded last, then trust desc, "
                    "then hop_index asc)")

    hops = r.get("received_chain") or []
    idxs = [h.get("hop_index") for h in hops]
    if idxs and idxs != list(range(1, len(hops) + 1)):
        fail(where, f"received_chain hop_index must be 1..N in order, got {idxs}")

    # A private IP is never a usable origin.  If one reached the candidate list
    # it must be flagged excluded - otherwise we could report 10.x as "the
    # sender's location", which is the worst overclaim this tool could make.
    private_ips = {h.get("from_ip") for h in hops if h.get("is_private_ip")}
    by_ip = {c.get("ip"): c for c in cands}
    for ip in private_ips - {None}:
        c = by_ip.get(ip)
        if c is not None and not c.get("excluded"):
            fail(where, f"private IP {ip} is in ip_candidates without "
                        f"excluded=true - it must never be selectable as origin")
    sel = (r.get("origin") or {}).get("selected_ip")
    if sel and sel in private_ips:
        fail(where, f"origin.selected_ip is the private address {sel}")

    ms = r.get("module_status") or {}
    bad = {k: v for k, v in ms.items() if v not in {"live", "stub", "error"}}
    if bad:
        fail(where, f"module_status has invalid values: {bad}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if not FIXTURE.exists():
        print(f"FATAL: fixture missing at {FIXTURE}")
        return 2
    reference = json.loads(FIXTURE.read_text(encoding="utf-8"))

    print("== fixture ==")
    check_invariants(reference, "fixture")
    print(f"   {len(reference)} top-level keys, {len(failures)} problem(s)")

    ref_shape = shape(reference)
    samples = sorted(SAMPLES.glob("*.eml"))
    if not samples:
        print(f"FATAL: no .eml files in {SAMPLES}")
        return 2

    print(f"\n== pipeline over {len(samples)} sample(s) ==")
    for path in samples:
        where = path.name
        before = len(failures)
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            result = pipeline.run_analysis(
                raw, source="file", filename=path.name, skip_geoip=True)
        except Exception as exc:  # a stub must never raise out of the pipeline
            fail(where, f"pipeline raised {type(exc).__name__}: {exc}")
            print(f"   FAIL {where}")
            continue

        compare(ref_shape, shape(result), "", where)
        check_invariants(result, where)

        new = len(failures) - before
        conf = ((result.get("origin") or {}).get("confidence"))
        band = (result.get("risk") or {}).get("band")
        stub = sum(1 for v in (result.get("module_status") or {}).values() if v == "stub")
        flag = "ok  " if new == 0 else "FAIL"
        print(f"   {flag} {where:<44} confidence={conf!s:<7} "
              f"band={band!s:<9} stubbed_modules={stub}")

    print("\n== wording ==")
    for name in ("STATEMENT_TEMPLATE", "NO_ORIGIN_STATEMENT"):
        text = getattr(m3_confidence, name, "")
        if not text or "Confidence" not in text:
            fail("confidence.py", f"{name} missing or missing the 'Confidence:' clause")
        else:
            print(f"   ok   {name} present ({len(text)} chars)")

    if args.verbose and notes:
        print("\n== notes (expected while modules are stubs) ==")
        for n in notes:
            print(f"   - {n}")

    print()
    if failures:
        print(f"FAILED - {len(failures)} contract problem(s):\n")
        for f in failures:
            print(f"  * {f}")
        return 1
    print(f"PASSED - shape conforms across {len(samples)} samples "
          f"({len(notes)} stub-related nulls, run with -v to list).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
