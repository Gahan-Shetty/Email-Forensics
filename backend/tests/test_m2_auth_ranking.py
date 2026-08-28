"""
M2 test suite.

Per docs/02-M2-auth-and-ip-ranking.md: "You are not blocked on M1: your test
file already contains hand-written hop dicts in the contract's shape. Code
against those, and swap to real parser output when M1 lands."

Each fixture below pairs (a) the real raw header block from the corresponding
samples/NN_*.eml file — so auth_checks parses genuine header text — with
(b) a hand-written `headers` dict and `received_chain` list in the exact
API_CONTRACT.md shape, standing in for M1's output.
"""

import pytest

from app.parsing.auth_checks import evaluate_authentication, VALID_RESULTS
from app.parsing.ip_ranking import rank_ip_candidates, is_trusted_receiver


# --------------------------------------------------------------------------- #
# Fixture: sample 01 — clean direct send, high confidence expected
# --------------------------------------------------------------------------- #

RAW_01 = """Received-SPF: pass (google.com: domain of billing@smallbiz-example.com designates 203.0.113.45 as permitted sender) client-ip=203.0.113.45;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@smallbiz-example.com header.s=default header.b=Ab12Cd34;
       spf=pass (google.com: domain of billing@smallbiz-example.com designates 203.0.113.45 as permitted sender) smtp.mailfrom=billing@smallbiz-example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=smallbiz-example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=smallbiz-example.com;
        s=default; t=1755000858;
        h=From:To:Subject:Date:Message-ID;
        bh=aGVsbG93b3JsZDEyMzQ1Njc4OTA=;
        b=Ab12Cd34EfGh56Ij78Kl90MnOp12QrSt34UvWx56YzAb78Cd90EfGh12IjKl34==
From: "SmallBiz Invoicing" <billing@smallbiz-example.com>
To: victim@gmail.com
Subject: Invoice #4471 for August services

body
"""

HEADERS_01 = {
    "from": {"display_name": "SmallBiz Invoicing", "address": "billing@smallbiz-example.com", "domain": "smallbiz-example.com"},
    "reply_to": None,
    "return_path": {"display_name": None, "address": "billing@smallbiz-example.com", "domain": "smallbiz-example.com"},
}

CHAIN_01 = [
    {
        "hop_index": 1,
        "raw": "from mail.smallbiz-example.com ([203.0.113.45]) by mx.google.com with ESMTPS id def456",
        "from_host": "mail.smallbiz-example.com",
        "from_ip": "203.0.113.45",
        "by_host": "mx.google.com",
        "by_ip": None,
        "protocol": "ESMTPS",
        "tls": True,
        "timestamp": "2026-08-12T15:14:20Z",
        "timestamp_raw": "Tue, 12 Aug 2026 15:14:20 -0700",
        "is_private_ip": False,
        "parse_ok": True,
    },
    {
        "hop_index": 2,
        "raw": "from localhost (localhost [127.0.0.1]) by mail.smallbiz-example.com (Postfix) with ESMTP id 1A2B3C4D5E",
        "from_host": "localhost",
        "from_ip": "127.0.0.1",
        "by_host": "mail.smallbiz-example.com",
        "by_ip": None,
        "protocol": "ESMTP",
        "tls": False,
        "timestamp": "2026-08-12T15:14:18Z",
        "timestamp_raw": "Tue, 12 Aug 2026 15:14:18 +0000",
        "is_private_ip": True,
        "parse_ok": True,
    },
]


# --------------------------------------------------------------------------- #
# Fixture: sample 02 — spoofed lookalike, hosted IP, private hop, SPF/DMARC fail
# --------------------------------------------------------------------------- #

RAW_02 = """Received-SPF: fail (google.com: domain of service@paypa1-secure.example does not designate 198.51.100.77 as permitted sender) client-ip=198.51.100.77;
Authentication-Results: mx.google.com;
       dkim=none (message not signed);
       spf=fail (google.com: domain of service@paypa1-secure.example does not designate 198.51.100.77 as permitted sender) smtp.mailfrom=service@paypa1-secure.example;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypa1-secure.example
From: "PayPal Security" <service@paypa1-secure.example>
Reply-To: recovery-team@paypa1-support.example
To: victim@gmail.com
Subject: Urgent: Your account has been limited

body
"""

HEADERS_02 = {
    "from": {"display_name": "PayPal Security", "address": "service@paypa1-secure.example", "domain": "paypa1-secure.example"},
    "reply_to": {"display_name": None, "address": "recovery-team@paypa1-support.example", "domain": "paypa1-support.example"},
    "return_path": {"display_name": None, "address": "service@paypa1-secure.example", "domain": "paypa1-secure.example"},
}

CHAIN_02 = [
    {
        "hop_index": 1,
        "raw": "from droplet-1042.digitalocean-example.net ([198.51.100.77]) by mx.google.com with ESMTP id jkl012",
        "from_host": "droplet-1042.digitalocean-example.net",
        "from_ip": "198.51.100.77",
        "by_host": "mx.google.com",
        "by_ip": None,
        "protocol": "ESMTP",
        "tls": False,
        "timestamp": "2026-08-13T10:02:08Z",
        "timestamp_raw": "Wed, 13 Aug 2026 03:02:08 -0700",
        "is_private_ip": False,
        "parse_ok": True,
    },
    {
        "hop_index": 2,
        "raw": "from [10.0.0.14] (unknown [10.0.0.14]) by droplet-1042.digitalocean-example.net (Postfix) with ESMTP id 9F8E7D6C5B",
        "from_host": None,
        "from_ip": "10.0.0.14",
        "by_host": "droplet-1042.digitalocean-example.net",
        "by_ip": None,
        "protocol": "ESMTP",
        "tls": False,
        "timestamp": "2026-08-13T10:02:05Z",
        "timestamp_raw": "Wed, 13 Aug 2026 10:02:05 +0000",
        "is_private_ip": True,
        "parse_ok": True,
    },
]


# --------------------------------------------------------------------------- #
# Fixture: sample 03 — VPN exit, softfail SPF, no DKIM
# --------------------------------------------------------------------------- #

RAW_03 = """Received-SPF: softfail (google.com: domain of transitioning ceo.office@corp-example.com discourages use of 192.0.2.199 as permitted sender) client-ip=192.0.2.199;
Authentication-Results: mx.google.com;
       dkim=none (message not signed);
       spf=softfail (google.com: domain of transitioning ceo.office@corp-example.com discourages use of 192.0.2.199 as permitted sender) smtp.mailfrom=ceo.office@corp-example.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=corp-example.com
From: "CEO Office" <ceo.office@corp-example.com>
Reply-To: ceo.office@corp-example.com
To: cfo@corp-example.com
Subject: Confidential - urgent wire transfer needed today

body
"""

HEADERS_03 = {
    "from": {"display_name": "CEO Office", "address": "ceo.office@corp-example.com", "domain": "corp-example.com"},
    "reply_to": {"display_name": None, "address": "ceo.office@corp-example.com", "domain": "corp-example.com"},
    "return_path": {"display_name": None, "address": "ceo.office@corp-example.com", "domain": "corp-example.com"},
}

CHAIN_03 = [
    {
        "hop_index": 1,
        "raw": "from vpn-exit-node-14.anonvpn-example.net ([192.0.2.199]) by mx.google.com with ESMTP id stu901",
        "from_host": "vpn-exit-node-14.anonvpn-example.net",
        "from_ip": "192.0.2.199",
        "by_host": "mx.google.com",
        "by_ip": None,
        "protocol": "ESMTP",
        "tls": False,
        "timestamp": "2026-08-14T12:41:00Z",
        "timestamp_raw": "Thu, 14 Aug 2026 05:41:00 -0700",
        "is_private_ip": False,
        "parse_ok": True,
    },
]


# --------------------------------------------------------------------------- #
# Fixture: sample 06 — zero Received headers, no auth headers at all
# --------------------------------------------------------------------------- #

RAW_06 = """From: "Prize Notification" <winner@lucky-draw-example.com>
To: victim@gmail.com
Subject: You have won a prize!

body
"""

HEADERS_06 = {
    "from": {"display_name": "Prize Notification", "address": "winner@lucky-draw-example.com", "domain": "lucky-draw-example.com"},
    "reply_to": None,
    "return_path": None,
}

CHAIN_06 = []


# --------------------------------------------------------------------------- #
# is_trusted_receiver
# --------------------------------------------------------------------------- #

class TestIsTrustedReceiver:

    def test_exact_match(self):
        assert is_trusted_receiver("google.com") is True

    def test_subdomain_match(self):
        assert is_trusted_receiver("mx.google.com") is True

    def test_none_input(self):
        assert is_trusted_receiver(None) is False

    def test_empty_string(self):
        assert is_trusted_receiver("") is False

    def test_untrusted_domain(self):
        assert is_trusted_receiver("droplet-1042.digitalocean-example.net") is False

    def test_suffix_spoofing_attack(self):
        """The attack this whole module exists to prevent: an attacker names
        their own relay so that 'google.com' is a SUBSTRING of the hostname,
        hoping naive `in` matching promotes them to provider_observed."""
        assert is_trusted_receiver("google.com.evil.tld") is False

    def test_suffix_spoofing_variant(self):
        assert is_trusted_receiver("notgoogle.com") is False

    def test_trailing_dot_normalized(self):
        assert is_trusted_receiver("google.com.") is True

    def test_case_insensitive(self):
        assert is_trusted_receiver("MX.GOOGLE.COM") is True


# --------------------------------------------------------------------------- #
# evaluate_authentication
# --------------------------------------------------------------------------- #

class TestEvaluateAuthentication:

    def test_sample_01_clean_pass(self):
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        assert auth["spf"]["result"] == "pass"
        assert auth["dkim"]["result"] == "pass"
        assert auth["dmarc"]["result"] == "pass"
        assert auth["alignment"]["spf_aligned"] is True
        assert auth["verified_by"] == "mx.google.com"
        assert auth["self_asserted_only"] is False

    def test_sample_02_spoofed_fail(self):
        auth = evaluate_authentication(RAW_02, HEADERS_02)
        assert auth["spf"]["result"] == "fail"
        assert auth["dmarc"]["result"] == "fail"
        assert auth["dmarc"]["policy"] == "reject"
        assert auth["verified_by"] == "mx.google.com"
        assert auth["alignment"]["spf_aligned"] is False
        assert auth["alignment"]["from_vs_returnpath_match"] is True  # return_path == from here

    def test_sample_03_softfail_no_dkim(self):
        auth = evaluate_authentication(RAW_03, HEADERS_03)
        assert auth["spf"]["result"] == "softfail"
        assert auth["dkim"]["result"] == "none"
        assert auth["dmarc"]["result"] == "fail"
        assert auth["dmarc"]["policy"] == "none"

    def test_sample_06_no_auth_headers_at_all(self):
        """No exception, and everything degrades to 'none' / null per the
        hard invariant: absent data is null, never a missing key or a crash."""
        auth = evaluate_authentication(RAW_06, HEADERS_06)
        assert auth["spf"]["result"] == "none"
        assert auth["dkim"]["result"] == "none"
        assert auth["dmarc"]["result"] == "none"
        assert auth["verified_by"] is None
        assert auth["self_asserted_only"] is False  # no AR headers at all, not "self-asserted"

    def test_self_asserted_only_when_untrusted_authserv(self):
        """An Authentication-Results header exists but its authserv-id is not
        a trusted receiver -> self_asserted_only must be True."""
        raw = (
            "Authentication-Results: mail.attacker-controlled.example;\n"
            "       spf=pass smtp.mailfrom=service@paypa1-secure.example;\n"
            "       dkim=pass header.i=@paypa1-secure.example;\n"
            "       dmarc=pass (p=NONE) header.from=paypa1-secure.example\n"
            "From: \"PayPal\" <service@paypa1-secure.example>\n\n"
            "body\n"
        )
        headers = {
            "from": {"display_name": None, "address": "service@paypa1-secure.example", "domain": "paypa1-secure.example"},
            "reply_to": None,
            "return_path": None,
        }
        auth = evaluate_authentication(raw, headers)
        assert auth["self_asserted_only"] is True
        assert auth["verified_by"] is None
        # Result is still reported (not suppressed), just flagged as unverified
        assert auth["spf"]["result"] == "pass"

    def test_multiple_authentication_results_picks_trusted_one(self):
        """Common with forwarding: an untrusted intermediate's AR header
        appears alongside a trusted one. Must not just take the first."""
        raw = (
            "Authentication-Results: relay.untrusted-forwarder.example;\n"
            "       spf=pass smtp.mailfrom=attacker@evil.example;\n"
            "       dmarc=pass (p=NONE) header.from=evil.example\n"
            "Authentication-Results: mx.google.com;\n"
            "       spf=fail smtp.mailfrom=attacker@evil.example;\n"
            "       dmarc=fail (p=REJECT) header.from=evil.example\n"
            "From: \"X\" <attacker@evil.example>\n\n"
            "body\n"
        )
        headers = {
            "from": {"display_name": None, "address": "attacker@evil.example", "domain": "evil.example"},
            "reply_to": None,
            "return_path": None,
        }
        auth = evaluate_authentication(raw, headers)
        assert auth["verified_by"] == "mx.google.com"
        assert auth["spf"]["result"] == "fail"
        assert auth["self_asserted_only"] is False

    def test_dkim_signature_present_but_unverified_stays_none(self):
        """DKIM-Signature header presence != verified pass. Only a trusted
        Authentication-Results dkim=pass should read as pass."""
        raw = (
            "DKIM-Signature: v=1; a=rsa-sha256; d=evil.example; s=sel1; b=abc==\n"
            "From: \"X\" <attacker@evil.example>\n\n"
            "body\n"
        )
        headers = {
            "from": {"display_name": None, "address": "attacker@evil.example", "domain": "evil.example"},
            "reply_to": None,
            "return_path": None,
        }
        auth = evaluate_authentication(raw, headers)
        assert auth["dkim"]["result"] == "none"
        assert auth["dkim"]["domain"] == "evil.example"  # claimed domain surfaced for context
        assert auth["dkim"]["selector"] == "sel1"

    def test_mechanism_objects_have_full_uniform_key_set(self):
        """Contract requires every mechanism (spf, dkim, dmarc, arc) to carry
        the same full key set (result, domain, selector, policy, raw, source),
        using None where a field doesn't apply to that mechanism — rather than
        each mechanism exposing a different subset of keys."""
        required_keys = {"result", "domain", "selector", "policy", "raw", "source"}
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        for mech in ("spf", "dkim", "dmarc", "arc"):
            assert required_keys.issubset(auth[mech].keys()), f"{mech} missing keys: {required_keys - auth[mech].keys()}"

    def test_mechanism_objects_full_key_set_even_when_empty(self):
        """Same check on sample 06, where almost everything is absent —
        keys must still all be present, values None rather than missing."""
        required_keys = {"result", "domain", "selector", "policy", "raw", "source"}
        auth = evaluate_authentication(RAW_06, HEADERS_06)
        for mech in ("spf", "dkim", "dmarc", "arc"):
            assert required_keys.issubset(auth[mech].keys())
            assert auth[mech]["result"] in VALID_RESULTS or auth[mech]["result"] == "none"

    def test_received_spf_fallback_when_no_ar_spf(self):
        raw = (
            "Received-SPF: fail (google.com: domain of x@evil.example does not designate 203.0.113.5 as permitted sender) client-ip=203.0.113.5;\n"
            "From: \"X\" <x@evil.example>\n\n"
            "body\n"
        )
        headers = {
            "from": {"display_name": None, "address": "x@evil.example", "domain": "evil.example"},
            "reply_to": None,
            "return_path": None,
        }
        auth = evaluate_authentication(raw, headers)
        assert auth["spf"]["result"] == "fail"
        assert auth["spf"]["source"] == "Received-SPF"


# --------------------------------------------------------------------------- #
# rank_ip_candidates
# --------------------------------------------------------------------------- #

class TestRankIpCandidates:

    def test_sample_01_provider_observed_top(self):
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        candidates = rank_ip_candidates(CHAIN_01, auth)
        assert candidates[0]["ip"] == "203.0.113.45"
        assert candidates[0]["trust_tier"] == "provider_observed"
        assert candidates[0]["excluded"] is False
        # private hop excluded but still present
        private_entries = [c for c in candidates if c["ip"] == "127.0.0.1"]
        assert len(private_entries) == 1
        assert private_entries[0]["excluded"] is True
        assert "private" in private_entries[0]["exclusion_reason"].lower()

    def test_sample_02_candidate0_is_hosted_ip(self):
        auth = evaluate_authentication(RAW_02, HEADERS_02)
        candidates = rank_ip_candidates(CHAIN_02, auth)
        assert candidates[0]["ip"] == "198.51.100.77"
        assert candidates[0]["excluded"] is False

    def test_sample_02_private_hop_excluded_but_present(self):
        auth = evaluate_authentication(RAW_02, HEADERS_02)
        candidates = rank_ip_candidates(CHAIN_02, auth)
        private_ips = [c for c in candidates if c["ip"] == "10.0.0.14"]
        assert len(private_ips) == 1
        assert private_ips[0]["excluded"] is True
        assert private_ips[0]["exclusion_reason"] == "RFC1918 private address, not externally routable"

    def test_empty_chain_returns_empty_list(self):
        auth = evaluate_authentication(RAW_06, HEADERS_06)
        candidates = rank_ip_candidates(CHAIN_06, auth)
        assert candidates == []

    def test_non_excluded_always_sorts_before_excluded(self):
        auth = evaluate_authentication(RAW_02, HEADERS_02)
        candidates = rank_ip_candidates(CHAIN_02, auth)
        excluded_flags = [c["excluded"] for c in candidates]
        # once True appears, everything after must also be True
        assert excluded_flags == sorted(excluded_flags)

    def test_sort_order_contract_guarantee(self):
        """If any non-excluded candidate exists, it is at index 0."""
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        candidates = rank_ip_candidates(CHAIN_01, auth)
        non_excluded = [c for c in candidates if not c["excluded"]]
        assert non_excluded
        assert candidates[0] == non_excluded[0]

    def test_duplicate_ip_marked_excluded(self):
        chain = [
            {
                "hop_index": 1, "raw": "", "from_host": "a.example", "from_ip": "203.0.113.9",
                "by_host": "mx.google.com", "by_ip": None, "protocol": None, "tls": False,
                "timestamp": None, "timestamp_raw": None, "is_private_ip": False, "parse_ok": True,
            },
            {
                "hop_index": 2, "raw": "", "from_host": "a.example", "from_ip": "203.0.113.9",
                "by_host": "relay.example", "by_ip": None, "protocol": None, "tls": False,
                "timestamp": None, "timestamp_raw": None, "is_private_ip": False, "parse_ok": True,
            },
        ]
        auth = evaluate_authentication(RAW_06, HEADERS_06)
        candidates = rank_ip_candidates(chain, auth)
        dupe = [c for c in candidates if c["hop_index"] == 2][0]
        assert dupe["excluded"] is True
        assert "Duplicate" in dupe["exclusion_reason"]

    def test_trust_score_clamped_and_rounded(self):
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        candidates = rank_ip_candidates(CHAIN_01, auth)
        for c in candidates:
            assert 0.0 <= c["trust_score"] <= 1.0
            assert round(c["trust_score"], 2) == c["trust_score"]

    def test_client_asserted_tier_for_unparseable_by_host(self):
        chain = [
            {
                "hop_index": 1, "raw": "", "from_host": "sender.example", "from_ip": "203.0.113.7",
                "by_host": None, "by_ip": None, "protocol": None, "tls": False,
                "timestamp": None, "timestamp_raw": None, "is_private_ip": False, "parse_ok": True,
            },
        ]
        auth = evaluate_authentication(RAW_06, HEADERS_06)
        candidates = rank_ip_candidates(chain, auth)
        assert candidates[0]["trust_tier"] == "client_asserted"

    def test_reasons_are_prose_not_codes(self):
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        candidates = rank_ip_candidates(CHAIN_01, auth)
        for c in candidates:
            for reason in c["reasons"]:
                assert isinstance(reason, str)
                assert "tier=" not in reason  # must not be a debug-style code dump

    def test_all_required_keys_present(self):
        auth = evaluate_authentication(RAW_01, HEADERS_01)
        candidates = rank_ip_candidates(CHAIN_01, auth)
        required_keys = {
            "ip", "hop_index", "trust_tier", "trust_score", "observed_by",
            "observed_by_is_trusted_receiver", "reasons", "excluded", "exclusion_reason",
        }
        for c in candidates:
            assert required_keys.issubset(c.keys())