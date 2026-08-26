"""M3's tests.  OWNER: M3 - only you edit this file.

Set GEOIP_PROVIDER=mock for these so they run offline and deterministically.
"""
from __future__ import annotations

import pytest

from backend.app.intel import confidence, geoip, risk_score

stub_conf = pytest.mark.skipif(confidence.IS_STUB, reason="M3 confidence still a stub")
stub_risk = pytest.mark.skipif(risk_score.IS_STUB, reason="M3 scoring still a stub")


def _geo(**over) -> dict:
    base = {"country": "Singapore", "country_code": "SG", "region": "Central",
            "city": "Singapore", "lat": 1.28, "lon": 103.85,
            "isp": "DigitalOcean, LLC", "org": "DigitalOcean", "asn": "AS14061",
            "is_datacenter": True, "is_proxy": False, "is_mobile": False,
            "lookup_source": "ip-api.com"}
    base.update(over)
    return base


def _candidate(**over) -> dict:
    base = {"ip": "203.0.113.9", "hop_index": 1, "trust_tier": "provider_observed",
            "trust_score": 0.86, "observed_by": "mx.google.com",
            "observed_by_is_trusted_receiver": True, "reasons": [],
            "excluded": False, "exclusion_reason": None}
    base.update(over)
    return base


CLEAN_CHAIN = {"hop_count": 3, "timestamps_monotonic": True, "backward_time_jumps": 0,
               "largest_gap_seconds": 2, "gaps_suspected": False,
               "malformed_hops": 0, "notes": []}
PASS_AUTH = {"spf": {"result": "pass"}, "dkim": {"result": "pass"},
             "dmarc": {"result": "pass"}, "self_asserted_only": False}


def test_infrastructure_classification():
    assert geoip.classify_infrastructure(_geo()) == "hosting"
    assert geoip.classify_infrastructure(_geo(org="NordVPN", is_datacenter=False)) == "vpn"
    assert geoip.classify_infrastructure(_geo(is_proxy=True)) in {"vpn", "tor"}
    assert geoip.classify_infrastructure(
        _geo(org="Google LLC", is_datacenter=False), "mail-wr1-f54.google.com") == "webmail_provider"
    assert geoip.classify_infrastructure(
        _geo(org="Airtel Broadband", isp="Bharti Airtel", is_datacenter=False)) == "residential_isp"


@stub_conf
def test_hosting_caps_confidence_at_medium():
    level, reasons = confidence.assess_confidence(_candidate(), _geo(), PASS_AUTH, CLEAN_CHAIN)
    assert level == "medium"
    assert reasons


@stub_conf
def test_clean_residential_direct_send_is_high():
    level, _ = confidence.assess_confidence(
        _candidate(), _geo(org="Bharti Airtel", isp="Bharti Airtel", is_datacenter=False),
        PASS_AUTH, CLEAN_CHAIN)
    assert level == "high"


@stub_conf
def test_vpn_forces_low():
    level, _ = confidence.assess_confidence(
        _candidate(), _geo(org="NordVPN", is_datacenter=False, is_proxy=True),
        PASS_AUTH, CLEAN_CHAIN)
    assert level == "low"


@stub_conf
def test_webmail_forces_low_even_when_all_auth_passes():
    """The case that catches naive builds: auth all green, origin still unknown."""
    level, _ = confidence.assess_confidence(
        _candidate(), _geo(org="Google LLC", is_datacenter=False), PASS_AUTH, CLEAN_CHAIN)
    assert level == "low"


@stub_conf
def test_no_candidates_uses_the_no_origin_statement():
    origin, map_hops = confidence.build_origin([], PASS_AUTH, CLEAN_CHAIN)
    assert origin["selected_ip"] is None
    assert origin["confidence"] == "low"
    assert origin["statement"] == confidence.NO_ORIGIN_STATEMENT
    assert map_hops == []


@stub_conf
def test_statement_wording_is_verbatim():
    origin, _ = confidence.build_origin([_candidate()], PASS_AUTH, CLEAN_CHAIN, skip_geoip=True)
    s = origin["statement"]
    assert "not a verified physical location of the sender" in s
    assert s.rstrip().endswith(".")


@stub_conf
def test_confidence_is_never_promoted():
    """Only demotion is allowed - a bad chain must not be rescued by good auth."""
    bad_chain = dict(CLEAN_CHAIN, malformed_hops=2, backward_time_jumps=1)
    level, _ = confidence.assess_confidence(_candidate(), _geo(is_datacenter=False),
                                            PASS_AUTH, bad_chain)
    assert level == "low"


@stub_risk
def test_scoring_all_signals_present_and_ordered():
    risk = risk_score.score_risk({"anomalies": []}, PASS_AUTH,
                                 {"infrastructure_type": "residential_isp", "geo": _geo(is_datacenter=False)},
                                 CLEAN_CHAIN, "")
    codes = [s["code"] for s in risk["signals"]]
    assert codes == [c for c, _, _ in risk_score.SIGNAL_DEFS]
    assert risk["score"] == 0
    assert risk["band"] == "low"


@stub_risk
def test_urgency_needs_two_keywords():
    base = ({"anomalies": []}, PASS_AUTH,
            {"infrastructure_type": "residential_isp", "geo": _geo(is_datacenter=False)},
            CLEAN_CHAIN)
    one = risk_score.score_risk(*base, "this is urgent")
    two = risk_score.score_risk(*base, "urgent: your account is suspended, act now")
    fired = lambda r: next(s["triggered"] for s in r["signals"] if s["code"] == "URGENCY_KEYWORDS")
    assert fired(one) is False
    assert fired(two) is True


@stub_risk
def test_band_boundaries():
    assert risk_score.band_for(0) == "low"
    assert risk_score.band_for(24) == "low"
    assert risk_score.band_for(25) == "medium"
    assert risk_score.band_for(49) == "medium"
    assert risk_score.band_for(50) == "high"
    assert risk_score.band_for(74) == "high"
    assert risk_score.band_for(75) == "critical"
    assert risk_score.band_for(100) == "critical"
