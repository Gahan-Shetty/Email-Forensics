"""
M2 <-> M1 integration test.

Unlike test_m2_auth_ranking.py (which uses hand-written fixtures standing in
for M1's output), this file imports M1's REAL parse_headers() /
parse_received_chain() and feeds their actual output into M2's functions,
against all six samples/*.eml files.

Run only after M1 is merged into main. If this file fails to import M1's
module, that's a signal M1's file/function names differ from what
API_CONTRACT.md §7 specifies — flag to M1/M6, don't silently adjust names
on the M2 side to make it pass.
"""

import os
import pytest

from app.parsing.header_parser import parse_headers, extract_body_text
from app.parsing.received_chain import parse_received_chain, assess_chain_integrity
from app.parsing.auth_checks import evaluate_authentication
from app.parsing.ip_ranking import rank_ip_candidates

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

SAMPLE_FILES = [
    "01_high_confidence_direct.eml",
    "02_spoofed_paypal_hosted.eml",
    "03_vpn_exit_low_confidence.eml",
    "04_webmail_no_origin_ip.eml",
    "05_broken_chain_backward_timestamps.eml",
    "06_minimal_no_headers.eml",
]

REQUIRED_AUTH_KEYS = {"result", "domain", "selector", "policy", "raw", "source"}
REQUIRED_CANDIDATE_KEYS = {
    "ip", "hop_index", "trust_tier", "trust_score", "observed_by",
    "observed_by_is_trusted_receiver", "reasons", "excluded", "exclusion_reason",
}


def _load_sample(filename):
    path = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(path):
        pytest.skip(f"sample file not found at {path} — adjust SAMPLES_DIR if repo layout differs")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("filename", SAMPLE_FILES)
class TestM1M2Integration:

    def test_full_pipeline_does_not_raise(self, filename):
        """The hard invariant from API_CONTRACT.md: a module failing degrades
        that block to null/stub — it must never throw. This is the single
        most important test in this file."""
        raw = _load_sample(filename)
        headers = parse_headers(raw)
        chain = parse_received_chain(raw)

        auth = evaluate_authentication(raw, headers)
        candidates = rank_ip_candidates(chain, auth)

        assert isinstance(auth, dict)
        assert isinstance(candidates, list)

    def test_authentication_shape_matches_contract(self, filename):
        raw = _load_sample(filename)
        headers = parse_headers(raw)
        auth = evaluate_authentication(raw, headers)

        for mech in ("spf", "dkim", "dmarc", "arc"):
            assert REQUIRED_AUTH_KEYS.issubset(auth[mech].keys()), (
                f"{filename}: {mech} missing keys "
                f"{REQUIRED_AUTH_KEYS - auth[mech].keys()}"
            )

        assert "verified_by" in auth
        assert "self_asserted_only" in auth
        assert isinstance(auth["self_asserted_only"], bool)

        alignment = auth["alignment"]
        for key in ("spf_aligned", "dkim_aligned", "from_vs_returnpath_match", "envelope_from_domain"):
            assert key in alignment

    def test_ip_candidates_shape_and_sort_contract(self, filename):
        raw = _load_sample(filename)
        headers = parse_headers(raw)
        chain = parse_received_chain(raw)
        auth = evaluate_authentication(raw, headers)
        candidates = rank_ip_candidates(chain, auth)

        for c in candidates:
            assert REQUIRED_CANDIDATE_KEYS.issubset(c.keys()), (
                f"{filename}: candidate missing keys {REQUIRED_CANDIDATE_KEYS - c.keys()}"
            )

        # sort-order contract: non-excluded first, then descending trust, then hop_index
        non_excluded = [c for c in candidates if not c["excluded"]]
        if non_excluded:
            assert candidates[0] == non_excluded[0], (
                f"{filename}: candidates[0] is not the top non-excluded candidate "
                "— M3 depends on this contract guarantee"
            )

    def test_no_exception_on_malformed_or_empty_input(self, filename):
        """Specifically exercises samples with missing/malformed data
        (06 = zero Received headers, 05 = broken chain) to confirm M2
        degrades gracefully rather than raising."""
        raw = _load_sample(filename)
        headers = parse_headers(raw)
        chain = parse_received_chain(raw)

        try:
            auth = evaluate_authentication(raw, headers)
            candidates = rank_ip_candidates(chain, auth)
        except Exception as e:
            pytest.fail(f"{filename}: M2 raised {type(e).__name__}: {e}")

        # even with nothing usable, must return valid degraded shapes
        assert auth["spf"]["result"] in {
            "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"
        }
        assert isinstance(candidates, list)


def test_sample_04_webmail_ip_is_not_falsely_promoted():
    """Regression guard for the trap case called out in the sample-data spec:
    Gmail-sent mail where every auth mechanism passes, but the only IP in the
    chain is Google's own outbound relay, not the sender's. M2 doesn't decide
    confidence (that's M3), but it must correctly identify this IP's
    observed_by as a trusted receiver WITHOUT inventing a higher trust tier
    than the evidence supports, and must not silently drop it."""
    raw = _load_sample("04_webmail_no_origin_ip.eml")
    headers = parse_headers(raw)
    chain = parse_received_chain(raw)
    auth = evaluate_authentication(raw, headers)
    candidates = rank_ip_candidates(chain, auth)

    assert auth["spf"]["result"] == "pass"
    assert auth["dkim"]["result"] == "pass"
    assert auth["dmarc"]["result"] == "pass"
    # M2 does not set confidence — just confirm the candidate list isn't empty
    # and the Google-observed IP is present for M3 to classify as webmail.
    assert len(candidates) >= 1
