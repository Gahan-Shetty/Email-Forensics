"""M1's tests.  OWNER: M1 - only you edit this file.

These are written to FAIL while your module is a stub (they are skipped via the
IS_STUB flag) and to pass once it works.  Delete the skip decorator when you
start, and use them as your definition of done.
"""
from __future__ import annotations

import pytest

from backend.app.parsing import header_parser, received_chain





def test_from_header_parsed(sample_phish):
    h = header_parser.parse_headers(sample_phish)
    assert h["from"]["address"] == "service@paypa1-secure.tld"
    assert h["from"]["domain"] == "paypa1-secure.tld"
    assert h["from"]["display_name"] == "PayPal Service"



def test_replyto_mismatch_anomaly_emitted(sample_phish):
    codes = {a["code"] for a in header_parser.parse_headers(sample_phish)["anomalies"]}
    assert "REPLYTO_DOMAIN_MISMATCH" in codes



def test_date_is_iso_utc(sample_phish):
    d = header_parser.parse_headers(sample_phish)["date"]
    assert d and d.endswith("Z")



def test_hop_one_is_closest_to_sender(sample_phish):
    """THE critical test. hop 1 must be the ORIGINATING server, not Google's."""
    chain = received_chain.parse_received_chain(sample_phish)
    assert chain[0]["hop_index"] == 1
    assert chain[0]["from_ip"] == "203.0.113.9"
    assert chain[0]["from_host"] == "mail.paypa1-secure.tld"



def test_private_ip_detection():
    assert received_chain.is_private_ip("10.20.30.40")
    assert received_chain.is_private_ip("127.0.0.1")
    assert received_chain.is_private_ip("192.168.1.1")
    assert received_chain.is_private_ip("100.64.0.1")   # CGNAT
    assert not received_chain.is_private_ip("203.0.113.9")
    assert received_chain.is_private_ip("not-an-ip")     # fail closed



def test_backward_timestamps_detected(samples):
    chain = received_chain.parse_received_chain(samples["05_broken_chain_backward_timestamps"])
    integrity = received_chain.assess_chain_integrity(chain)
    assert integrity["backward_time_jumps"] > 0
    assert not integrity["timestamps_monotonic"]



def test_no_received_headers_returns_empty(samples):
    assert received_chain.parse_received_chain(samples["06_minimal_no_headers"]) == []
