"""M2's tests.  OWNER: M2 - only you edit this file."""
from __future__ import annotations

import pytest

from backend.app.parsing import auth_checks, ip_ranking

stub_auth = pytest.mark.skipif(auth_checks.IS_STUB, reason="M2 auth still a stub")
stub_rank = pytest.mark.skipif(ip_ranking.IS_STUB, reason="M2 ranking still a stub")


@stub_auth
def test_spf_dmarc_fail_read_from_trusted_receiver(sample_phish):
    a = auth_checks.evaluate_authentication(sample_phish, {"from": {"domain": "paypa1-secure.tld"}})
    assert a["spf"]["result"] == "fail"
    assert a["dmarc"]["result"] == "fail"
    assert a["dmarc"]["policy"] == "reject"
    assert a["verified_by"] == "mx.google.com"
    assert a["self_asserted_only"] is False


@stub_auth
def test_all_pass_sample(samples):
    a = auth_checks.evaluate_authentication(
        samples["01_high_confidence_direct"], {"from": {"domain": "smallbiz-supplies.co.in"}})
    assert a["spf"]["result"] == "pass"
    assert a["dkim"]["result"] == "pass"
    assert a["alignment"]["spf_aligned"] is True


@stub_auth
def test_no_auth_headers_is_not_an_error(samples):
    a = auth_checks.evaluate_authentication(samples["06_minimal_no_headers"],
                                            {"from": {"domain": "example.com"}})
    assert a["spf"]["result"] == "none"
    assert a["verified_by"] is None


@stub_rank
def test_trusted_receiver_matching():
    assert ip_ranking.is_trusted_receiver("mx.google.com")
    assert ip_ranking.is_trusted_receiver("MX.GOOGLE.COM")
    assert ip_ranking.is_trusted_receiver("eur01.protection.outlook.com")
    assert not ip_ranking.is_trusted_receiver("relay.shadyhost.tld")
    # the attack this must resist: suffix spoofing
    assert not ip_ranking.is_trusted_receiver("google.com.evil.tld")
    assert not ip_ranking.is_trusted_receiver(None)


@stub_rank
def test_top_candidate_is_originating_ip():
    chain = [
        {"hop_index": 1, "from_ip": "203.0.113.9", "from_host": "mail.evil.tld",
         "by_host": "mx.google.com", "is_private_ip": False, "parse_ok": True, "tls": True,
         "timestamp": "2026-08-20T09:00:01Z"},
        {"hop_index": 2, "from_ip": "10.0.0.5", "from_host": None,
         "by_host": "inbox.google.com", "is_private_ip": True, "parse_ok": True, "tls": False,
         "timestamp": "2026-08-20T09:00:02Z"},
    ]
    auth = {"self_asserted_only": False}
    out = ip_ranking.rank_ip_candidates(chain, auth)
    usable = [c for c in out if not c["excluded"]]
    assert usable[0]["ip"] == "203.0.113.9"
    assert usable[0]["trust_tier"] == "provider_observed"
    assert any(c["ip"] == "10.0.0.5" and c["excluded"] for c in out)


@stub_rank
def test_empty_chain_returns_empty_list():
    assert ip_ranking.rank_ip_candidates([], {"self_asserted_only": False}) == []
