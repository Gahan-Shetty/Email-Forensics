"""
M2 — ip_ranking.py
Owner: M2

Fills response["ip_candidates"]. See API_CONTRACT.md §3/§3.4/§5 and
docs/02-M2-auth-and-ip-ranking.md.

Core idea (say this out loud in the demo): a sender controls every byte of
every header they write. They cannot control what the RECEIVING server
writes when it accepts the connection, because that server observed the
actual TCP source address. So an IP is exactly as trustworthy as the server
that recorded it.
"""

from app.core.config import TRUSTED_RECEIVER_DOMAINS

IS_STUB = False

TIER_BASE_SCORE = {
    "provider_observed": 0.85,
    "transit_relay": 0.55,
    "client_asserted": 0.25,
    "unverifiable": 0.05,
}


def is_trusted_receiver(hostname):
    """
    Label-boundary match only. Substring matching is a security bug:
    "google.com" in "google.com.evil.tld" is True — that must return False.
    An attacker naming their relay google.com.evil.tld must NOT be promoted
    to provider_observed.
    """
    if not hostname:
        return False
    h = hostname.strip().rstrip(".").lower()
    return any(h == d or h.endswith("." + d) for d in TRUSTED_RECEIVER_DOMAINS)


def _classify_tier(hop, hop_index):
    by_host = hop.get("by_host")
    from_host = hop.get("from_host")

    if is_trusted_receiver(by_host):
        return "provider_observed"

    if by_host and "." in by_host and by_host != from_host:
        return "transit_relay"

    # first hop (closest to sender) with no by_host, or by_host unparseable
    if hop_index == 1 and (not by_host or by_host == from_host):
        return "client_asserted"

    return "unverifiable"


def _adjust_score(base, hop, auth):
    score = base

    if hop.get("tls"):
        score += 0.05

    if hop.get("timestamp") and hop.get("parse_ok", True):
        # "consistent with neighbours" is assessed at the chain level by M1
        # (chain_integrity). At the per-hop level we treat "has a parsed,
        # present timestamp" as the proxy for this bonus, since ip_ranking
        # does not receive chain_integrity as an argument.
        score += 0.05

    if auth and auth.get("self_asserted_only"):
        score -= 0.10

    if not hop.get("parse_ok", True):
        score -= 0.05

    return round(max(0.0, min(1.0, score)), 2)


def _reasons_for(tier, hop, ip, excluded, exclusion_reason):
    if excluded:
        return [exclusion_reason]

    by_host = hop.get("by_host")

    if tier == "provider_observed":
        return [
            f"Recorded by {by_host}, which we treat as a trusted receiving provider.",
            "Public routable address observed directly by that provider's own infrastructure.",
        ]
    if tier == "transit_relay":
        return [
            f"Recorded by {by_host}, an intermediate mail server we cannot independently verify as trustworthy.",
            "Treated as corroborating evidence, not confirmed provider observation.",
        ]
    if tier == "client_asserted":
        return [
            "This is the sender's own first hop; no independent receiving server confirmed this address.",
            "Only the sender's client claims this origin.",
        ]
    return [
        "Hop could not be reliably parsed or corroborated by any trusted observer.",
    ]


def rank_ip_candidates(chain: list, auth: dict) -> list:
    """-> response["ip_candidates"]

    Contract guarantee: if any non-excluded candidate exists, it is at
    index 0 after sorting. M3 reads candidates[0] and does not re-sort.
    """
    if not chain:
        return []

    candidates = []
    seen_ips = {}  # ip -> lowest hop_index already emitted, for dedup

    for hop in chain:
        ip = hop.get("from_ip")
        if not ip:
            continue

        hop_index = hop.get("hop_index")
        excluded = False
        exclusion_reason = None

        if hop.get("is_private_ip"):
            excluded = True
            exclusion_reason = "RFC1918 private address, not externally routable"
        elif ip in seen_ips:
            excluded = True
            exclusion_reason = f"Duplicate of IP already observed at hop {seen_ips[ip]}"

        tier = _classify_tier(hop, hop_index)
        base = TIER_BASE_SCORE[tier]
        trust_score = _adjust_score(base, hop, auth)

        by_host = hop.get("by_host")
        observed_by_is_trusted = is_trusted_receiver(by_host)

        candidates.append({
            "ip": ip,
            "hop_index": hop_index,
            "trust_tier": tier,
            "trust_score": trust_score,
            "observed_by": by_host,
            "observed_by_is_trusted_receiver": observed_by_is_trusted,
            "reasons": _reasons_for(tier, hop, ip, excluded, exclusion_reason),
            "excluded": excluded,
            "exclusion_reason": exclusion_reason,
        })

        if ip not in seen_ips:
            seen_ips[ip] = hop_index

    candidates.sort(key=lambda c: (c["excluded"], -c["trust_score"], c["hop_index"]))
    return candidates