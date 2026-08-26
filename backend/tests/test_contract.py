"""Contract conformance.  OWNER: M6.

These tests are the safety net for parallel work: they assert that whatever the
six modules currently return still fits the frozen contract.  They pass against
pure stubs and must KEEP passing as each member fills their module in.

Run from the repo root:   python -m pytest backend/tests -q
"""
from __future__ import annotations

from backend.app.pipeline import run_analysis
from backend.app.schemas import AnalysisResponse

CONFIDENCE = {"high", "medium", "low"}
BANDS = {"low", "medium", "high", "critical"}


def _analyse(raw: str) -> dict:
    return run_analysis(raw, skip_geoip=True)


def test_fixture_validates_against_schema(fixture_response):
    """The mock the frontend builds against must satisfy the real schema."""
    AnalysisResponse.model_validate(fixture_response)


def test_pipeline_output_validates(sample_phish):
    AnalysisResponse.model_validate(_analyse(sample_phish))


def test_every_sample_runs_without_raising(samples):
    """No input may 500 the pipeline - including the header-less one."""
    for name, raw in samples.items():
        out = _analyse(raw)
        AnalysisResponse.model_validate(out), f"{name} failed validation"


def test_confidence_never_null(samples):
    for name, raw in samples.items():
        assert _analyse(raw)["origin"]["confidence"] in CONFIDENCE, name


def test_origin_statement_never_empty(samples):
    for name, raw in samples.items():
        assert _analyse(raw)["origin"]["statement"].strip(), name


def test_statement_carries_confidence_word(samples):
    """Contract section 6: the statement must name its own confidence level."""
    for name, raw in samples.items():
        out = _analyse(raw)
        assert out["origin"]["confidence"] in out["origin"]["statement"].lower(), name


def test_risk_always_has_five_signals(samples):
    for name, raw in samples.items():
        risk = _analyse(raw)["risk"]
        assert len(risk["signals"]) == 5, name
        assert risk["band"] in BANDS, name
        assert 0 <= risk["score"] <= 100, name


def test_every_map_hop_is_confidence_labelled(samples):
    """A bare pin with no confidence label is a contract violation."""
    for name, raw in samples.items():
        for hop in _analyse(raw)["map_hops"]:
            assert hop["confidence"] in CONFIDENCE, name


def test_ip_candidates_sorted_best_first(samples):
    """M2 guarantees index 0 is the most credible non-excluded candidate."""
    for name, raw in samples.items():
        usable = [c for c in _analyse(raw)["ip_candidates"] if not c["excluded"]]
        scores = [c["trust_score"] for c in usable]
        assert scores == sorted(scores, reverse=True), name


def test_private_ips_are_excluded(samples):
    """Once M2 is live, no RFC1918 address may be chosen as the origin."""
    for name, raw in samples.items():
        out = _analyse(raw)
        for c in out["ip_candidates"]:
            if c["ip"].startswith(("10.", "192.168.", "127.")):
                assert c["excluded"], f"{name}: {c['ip']} must be excluded"


def test_timings_present(sample_phish):
    t = _analyse(sample_phish)["timings_ms"]
    assert t["total"] >= 0 and "parse" in t
