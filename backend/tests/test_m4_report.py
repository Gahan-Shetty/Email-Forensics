"""M4's tests.  OWNER: M4 - only you edit this file."""
from __future__ import annotations

import pytest

from backend.app.report import custody_log, report_builder

stub_rep = pytest.mark.skipif(report_builder.IS_STUB, reason="M4 report still a stub")
stub_cust = pytest.mark.skipif(custody_log.IS_STUB, reason="M4 custody still a stub")


def test_hash_is_stable_across_key_order(fixture_response):
    """The whole tamper-evidence claim rests on this. Test it even while stubbed."""
    a = dict(fixture_response)
    b = {k: a[k] for k in reversed(list(a.keys()))}
    assert report_builder.canonical_evidence_hash(a) == report_builder.canonical_evidence_hash(b)


def test_hash_ignores_volatile_fields(fixture_response):
    """Timings change every run; they must not change the evidence hash."""
    a = dict(fixture_response)
    b = dict(fixture_response, timings_ms={"parse": 999, "auth": 999, "geoip": 999,
                                           "score": 999, "report": 999, "total": 999})
    assert report_builder.canonical_evidence_hash(a) == report_builder.canonical_evidence_hash(b)


def test_hash_changes_when_evidence_changes(fixture_response):
    a = dict(fixture_response)
    tampered = dict(fixture_response)
    tampered["origin"] = dict(a["origin"], selected_ip="8.8.8.8")
    assert report_builder.canonical_evidence_hash(a) != report_builder.canonical_evidence_hash(tampered)


def test_hash_is_64_hex_chars(fixture_response):
    h = report_builder.canonical_evidence_hash(fixture_response)
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


@stub_rep
def test_report_carries_the_statement_verbatim(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    blob = str(payload)
    assert fixture_response["origin"]["statement"] in blob


@stub_rep
def test_report_includes_all_limitations(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    assert len(payload["limitations"]) == len(report_builder.LIMITATIONS_TEXT)


@stub_rep
def test_report_includes_every_confidence_reason(fixture_response):
    blob = str(report_builder.build_report_payload(fixture_response))
    for reason in fixture_response["origin"]["confidence_reasons"]:
        assert reason in blob


@stub_cust
def test_custody_entries_increment_and_chain(tmp_path, monkeypatch):
    from backend.app.core import config
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", tmp_path / "log.jsonl")
    n1, prev1 = custody_log.append_custody_entry("id-1", "a" * 64, {})
    n2, prev2 = custody_log.append_custody_entry("id-2", "b" * 64, {})
    assert (n1, n2) == (1, 2)
    assert prev1 is None and prev2 is not None
    assert custody_log.verify_custody_chain()["intact"] is True


@stub_cust
def test_tampering_breaks_the_chain(tmp_path, monkeypatch):
    """The live demo moment - prove it works before you show it."""
    from backend.app.core import config
    log = tmp_path / "log.jsonl"
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", log)
    custody_log.append_custody_entry("id-1", "a" * 64, {})
    custody_log.append_custody_entry("id-2", "b" * 64, {})
    lines = log.read_text().splitlines()
    lines[0] = lines[0].replace("a" * 64, "c" * 64)
    log.write_text("\n".join(lines) + "\n")
    result = custody_log.verify_custody_chain()
    assert result["intact"] is False
    assert result["broken_at"] is not None
