"""M4's tests.  OWNER: M4 - only you edit this file.

Everything here runs against `fixture_response` (fixtures/sample_response.json,
provided by M6's conftest) or against hand-written dicts defined below, so none
of it depends on M1/M2/M3 being finished.  That is deliberate: M4 can go green
on day one.

Run just these:      python -m pytest backend/tests/test_m4_report.py -q
Run one by name:     python -m pytest backend/tests/test_m4_report.py -q -k tamper
"""
from __future__ import annotations

import json

import pytest

from backend.app.report import custody_log, pdf_renderer, report_builder

stub_rep = pytest.mark.skipif(report_builder.IS_STUB, reason="M4 report still a stub")
stub_cust = pytest.mark.skipif(custody_log.IS_STUB, reason="M4 custody still a stub")

reportlab_missing = False
try:                     # the PDF tests skip rather than fail on a bare machine
    import reportlab     # noqa: F401
except ImportError:
    reportlab_missing = True
needs_reportlab = pytest.mark.skipif(reportlab_missing, reason="reportlab not installed")


# --------------------------------------------------------------------------- #
# fixtures owned by M4
# --------------------------------------------------------------------------- #
@pytest.fixture
def minimal_analysis() -> dict:
    """The samples/06_minimal_no_headers.eml shape: almost nothing populated,
    several blocks null.  This is the input that breaks a report generator
    written against happy-path data only, so it is a first-class test input.

    Hand-written on purpose - it must not depend on M1's parser working.
    """
    return {
        "schema_version": "1.0",
        "analysis_id": "min-0001",
        "analyzed_at": "2026-08-27T00:00:00Z",
        "input": {"source": "paste", "filename": None, "byte_size": 61, "sha256": "0" * 64},
        "headers": {
            "from": {"display_name": None, "address": "someone@example.com",
                     "domain": "example.com"},
            "reply_to": None, "return_path": None, "to": [], "cc": [],
            "subject": None, "message_id": None, "message_id_domain": None,
            "date": None, "date_raw": None, "x_mailer": None,
            "raw_header_count": 2, "missing_headers": ["Received", "Message-ID", "Date"],
            "body_preview": "", "anomalies": [],
        },
        "received_chain": [],
        "chain_integrity": None,          # null while M1 is mid-build
        "authentication": None,           # null while M2 is mid-build
        "ip_candidates": [],
        "origin": {
            "selected_ip": None, "selected_from_hop": None, "geo": {},
            "infrastructure_type": "unknown", "confidence": "low",
            "confidence_reasons": ["No externally observed sending IP was recoverable."],
            "statement": ("No externally observed sending IP could be recovered from "
                          "this message's headers. Origin infrastructure could not be "
                          "geolocated. Confidence: low."),
        },
        "map_hops": [],
        "risk": {"score": 10, "band": "low", "verdict": "inconclusive", "signals": []},
        "report": None,
        "warnings": [],
        "timings_ms": {},
        "module_status": {},
    }


@pytest.fixture
def hostile_analysis(minimal_analysis) -> dict:
    """Markup and non-ASCII in message-derived text. reportlab parses Paragraph
    content as XML, so an unescaped '&' or '<' raises - and real phishing
    subject lines contain both."""
    a = json.loads(json.dumps(minimal_analysis))
    a["headers"]["subject"] = "<b>Urgent</b> Payment & Invoice ₹500 <script>x</script>"
    a["headers"]["from"]["display_name"] = 'Ravi "R&D" <spoof@evil.tld>'
    return a


@pytest.fixture
def custody_tmp(tmp_path, monkeypatch):
    """Point the custody log at a tmp file.  Patches the config MODULE attribute,
    which is why custody_log.py resolves the path at call time."""
    from backend.app.core import config
    path = tmp_path / "custody_log.jsonl"
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", path)
    return path


# --------------------------------------------------------------------------- #
# the hash - these must pass even while everything else is a stub
# --------------------------------------------------------------------------- #
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


def test_hash_ignores_every_excluded_field(fixture_response):
    """module_status, report and warnings are our tool's own diagnostics, not
    evidence.  warnings especially: pipeline.py appends to it AFTER hashing, so
    if it were hashed the stored digest would not survive recomputation at
    /report/{id}.json."""
    base = report_builder.canonical_evidence_hash(fixture_response)
    for field, value in [
        ("module_status", {"parsing": "error"}),
        ("report", {"report_id": "RPT-9999-9999"}),
        ("warnings", ["custody log write failed"]),
        ("timings_ms", {"total": 12345}),
    ]:
        mutated = dict(fixture_response, **{field: value})
        assert report_builder.canonical_evidence_hash(mutated) == base, field


def test_hash_changes_when_evidence_changes(fixture_response):
    a = dict(fixture_response)
    tampered = dict(fixture_response)
    tampered["origin"] = dict(a["origin"], selected_ip="8.8.8.8")
    assert report_builder.canonical_evidence_hash(a) != report_builder.canonical_evidence_hash(tampered)


@pytest.mark.parametrize("block,key,value", [
    ("headers", "subject", "Different subject"),
    ("risk", "score", 1),
    ("origin", "confidence", "high"),
    ("input", "sha256", "f" * 64),
])
def test_hash_covers_every_evidence_block(fixture_response, block, key, value):
    """Changing anything that IS evidence must move the digest."""
    base = report_builder.canonical_evidence_hash(fixture_response)
    mutated = dict(fixture_response)
    mutated[block] = dict(fixture_response[block], **{key: value})
    assert report_builder.canonical_evidence_hash(mutated) != base


def test_hash_is_64_hex_chars(fixture_response):
    h = report_builder.canonical_evidence_hash(fixture_response)
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def test_hash_survives_non_ascii_and_unhashable_types(minimal_analysis):
    """ensure_ascii + default=str mean a stray datetime or a rupee sign cannot
    take down the hash."""
    import datetime as dt
    a = dict(minimal_analysis)
    a["headers"] = dict(a["headers"], subject="Facture €250 — échéance")
    a["analyzed_at"] = dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc)
    assert len(report_builder.canonical_evidence_hash(a)) == 64


# --------------------------------------------------------------------------- #
# report payload
# --------------------------------------------------------------------------- #
@stub_rep
def test_report_carries_the_statement_verbatim(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    blob = str(payload)
    assert fixture_response["origin"]["statement"] in blob


@stub_rep
def test_statement_is_not_reworded_or_truncated(fixture_response):
    """API_CONTRACT.md section 6: verbatim means verbatim, in both places it appears."""
    original = fixture_response["origin"]["statement"]
    payload = report_builder.build_report_payload(fixture_response)
    assert payload["summary"]["origin_statement"] == original
    assert payload["origin_analysis"]["statement"] == original


@stub_rep
def test_report_includes_all_limitations(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    assert len(payload["limitations"]) == len(report_builder.LIMITATIONS_TEXT)
    assert payload["limitations"] == report_builder.LIMITATIONS_TEXT


@stub_rep
def test_report_includes_every_confidence_reason(fixture_response):
    blob = str(report_builder.build_report_payload(fixture_response))
    for reason in fixture_response["origin"]["confidence_reasons"]:
        assert reason in blob


@stub_rep
def test_report_has_all_eight_sections(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    for key, _title in report_builder.SECTION_ORDER:
        assert key in payload, key


@stub_rep
def test_report_keeps_excluded_candidates_with_reasons(fixture_response):
    """Showing what we rejected, and why, is the part that proves we ranked the
    candidates instead of grabbing the first IP."""
    payload = report_builder.build_report_payload(fixture_response)
    cands = payload["origin_analysis"]["candidates"]
    assert len(cands) == len(fixture_response["ip_candidates"])
    for c in cands:
        if c["excluded"]:
            assert c["exclusion_reason"]


@stub_rep
def test_report_lists_only_triggered_signals_in_summary(fixture_response):
    payload = report_builder.build_report_payload(fixture_response)
    expected = [s for s in fixture_response["risk"]["signals"] if s["triggered"]]
    assert payload["summary"]["signals_triggered_count"] == len(expected)
    assert payload["summary"]["signals_evaluated_count"] == len(fixture_response["risk"]["signals"])


@stub_rep
def test_report_is_pure_and_repeatable(fixture_response):
    """Called at GET /report/{id}.json, so it must not write files or mutate the
    analysis, and two calls must agree on the digest."""
    snapshot = json.dumps(fixture_response, sort_keys=True)
    a = report_builder.build_report_payload(fixture_response)
    b = report_builder.build_report_payload(fixture_response)
    assert a["integrity"]["evidence_sha256"] == b["integrity"]["evidence_sha256"]
    assert json.dumps(fixture_response, sort_keys=True) == snapshot


@stub_rep
def test_report_survives_a_nearly_empty_message(minimal_analysis):
    """samples/06 - no Received headers, null auth and chain blocks."""
    payload = report_builder.build_report_payload(minimal_analysis)
    assert payload["routing"]["hops"] == []
    assert payload["origin_analysis"]["selected_ip"] is None
    assert payload["origin_analysis"]["location"] == "Location not determined"
    assert payload["summary"]["origin_statement"].endswith("Confidence: low.")
    assert len(payload["limitations"]) == 5


@stub_rep
def test_report_survives_completely_empty_input():
    """Belt and braces: an empty dict must still produce a well-formed document
    rather than a 500 at the report endpoint."""
    payload = report_builder.build_report_payload({})
    assert payload["case_header"]["report_id"].startswith("RPT-")
    assert payload["limitations"]
    assert len(payload["integrity"]["evidence_sha256"]) == 64


@stub_rep
def test_report_is_json_serialisable(fixture_response, minimal_analysis):
    """It is served straight out of FastAPI, so anything unserialisable is a 500."""
    for analysis in (fixture_response, minimal_analysis):
        json.dumps(report_builder.build_report_payload(analysis))


@stub_rep
def test_report_id_comes_from_the_custody_entry(fixture_response):
    """The pipeline writes report.report_id after the custody append; the
    document must reuse it rather than inventing a second identifier."""
    payload = report_builder.build_report_payload(fixture_response)
    assert payload["case_header"]["report_id"] == fixture_response["report"]["report_id"]


@stub_rep
def test_report_id_marks_an_unlogged_analysis(minimal_analysis):
    payload = report_builder.build_report_payload(minimal_analysis)
    assert payload["case_header"]["report_id"].endswith("-0000")
    assert payload["integrity"]["custody_log_entry"] is None


@stub_rep
def test_self_asserted_auth_is_flagged_loudly(fixture_response):
    a = json.loads(json.dumps(fixture_response))
    a["authentication"]["self_asserted_only"] = True
    payload = report_builder.build_report_payload(a)
    assert payload["authentication"]["self_asserted_only"] is True
    assert "no evidentiary weight" in payload["authentication"]["self_asserted_warning"]


# --------------------------------------------------------------------------- #
# custody log
# --------------------------------------------------------------------------- #
@stub_cust
def test_custody_entries_increment_and_chain(custody_tmp):
    n1, prev1 = custody_log.append_custody_entry("id-1", "a" * 64, {})
    n2, prev2 = custody_log.append_custody_entry("id-2", "b" * 64, {})
    assert (n1, n2) == (1, 2)
    assert prev1 is None and prev2 is not None
    assert custody_log.verify_custody_chain()["intact"] is True


@stub_cust
def test_custody_entry_shape_is_frozen(custody_tmp):
    """The /api/v1/custody-log endpoint returns these objects verbatim, so the
    key set is part of the API surface."""
    custody_log.append_custody_entry("id-1", "a" * 64, {"filename": "x.eml", "byte_size": 12})
    entry = custody_log.read_custody_log()[0]
    assert set(entry) == {
        "entry_no", "recorded_at", "analysis_id", "evidence_sha256", "report_id",
        "actor", "meta", "previous_entry_hash", "entry_hash",
    }
    assert entry["report_id"].endswith("-0001")
    assert entry["previous_entry_hash"] is None
    assert entry["meta"]["filename"] == "x.eml"


@stub_cust
def test_each_entry_links_to_the_one_before_it(custody_tmp):
    for i in range(4):
        custody_log.append_custody_entry(f"id-{i}", f"{i}" * 64, {})
    entries = custody_log.read_custody_log()
    assert [e["entry_no"] for e in entries] == [1, 2, 3, 4]
    for previous, current in zip(entries, entries[1:]):
        assert current["previous_entry_hash"] == previous["entry_hash"]


@stub_cust
def test_empty_log_verifies_as_intact(custody_tmp):
    result = custody_log.verify_custody_chain()
    assert result == {"entries": 0, "intact": True, "broken_at": None,
                      "detail": result["detail"]}
    assert custody_log.read_custody_log() == []


@stub_cust
def test_tampering_breaks_the_chain(custody_tmp):
    """The live demo moment - prove it works before you show it."""
    custody_log.append_custody_entry("id-1", "a" * 64, {})
    custody_log.append_custody_entry("id-2", "b" * 64, {})
    lines = custody_tmp.read_text().splitlines()
    lines[0] = lines[0].replace("a" * 64, "c" * 64)
    custody_tmp.write_text("\n".join(lines) + "\n")
    result = custody_log.verify_custody_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 1


@stub_cust
def test_deleting_an_entry_is_detected(custody_tmp):
    """Removing a line renumbers the sequence - catching that is check 3."""
    for i in range(3):
        custody_log.append_custody_entry(f"id-{i}", f"{i}" * 64, {})
    lines = custody_tmp.read_text().splitlines()
    custody_tmp.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = custody_log.verify_custody_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 3


@stub_cust
def test_truncated_line_is_detected_not_crashed_on(custody_tmp):
    custody_log.append_custody_entry("id-1", "a" * 64, {})
    with custody_tmp.open("a", encoding="utf-8") as fh:
        fh.write('{"entry_no": 2, "partial"\n')
    result = custody_log.verify_custody_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 2
    assert custody_log.read_custody_log() == [custody_log.read_custody_log()[0]]


@stub_cust
def test_append_never_raises_when_the_path_is_unwritable(tmp_path, monkeypatch):
    """A failed custody write must not lose the analysis the user waited for."""
    from backend.app.core import config
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("i am a file")
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", blocker / "log.jsonl")
    assert custody_log.append_custody_entry("id-1", "a" * 64, {}) == (0, None)


@stub_cust
def test_missing_log_reads_as_empty(tmp_path, monkeypatch):
    from backend.app.core import config
    monkeypatch.setattr(config, "CUSTODY_LOG_PATH", tmp_path / "nope" / "log.jsonl")
    assert custody_log.read_custody_log() == []
    assert custody_log.verify_custody_chain()["intact"] is True


# --------------------------------------------------------------------------- #
# PDF - last, and skipped when reportlab is absent
# --------------------------------------------------------------------------- #
@needs_reportlab
@stub_rep
def test_pdf_renders_the_fixture(tmp_path, fixture_response):
    out = tmp_path / "report.pdf"
    payload = report_builder.build_report_payload(fixture_response)
    assert pdf_renderer.render_pdf(payload, str(out)) == str(out)
    assert out.read_bytes().startswith(b"%PDF")
    assert out.stat().st_size > 2000


@needs_reportlab
@stub_rep
def test_pdf_renders_a_nearly_empty_message(tmp_path, minimal_analysis):
    out = tmp_path / "minimal.pdf"
    pdf_renderer.render_pdf(report_builder.build_report_payload(minimal_analysis), str(out))
    assert out.read_bytes().startswith(b"%PDF")


@needs_reportlab
@stub_rep
def test_pdf_escapes_markup_in_message_text(tmp_path, hostile_analysis):
    """An unescaped '&' or '<' from a real phishing subject line raises inside
    reportlab. This is the test that stops that happening on stage."""
    out = tmp_path / "hostile.pdf"
    pdf_renderer.render_pdf(report_builder.build_report_payload(hostile_analysis), str(out))
    assert out.read_bytes().startswith(b"%PDF")


@pytest.mark.skipif(not reportlab_missing, reason="reportlab is installed")
def test_missing_reportlab_degrades_to_501(tmp_path, fixture_response):
    """main.py catches NotImplementedError and returns a clean 501, so a
    teammate without reportlab still gets a working JSON report."""
    with pytest.raises(NotImplementedError):
        pdf_renderer.render_pdf(report_builder.build_report_payload(fixture_response),
                                str(tmp_path / "x.pdf"))