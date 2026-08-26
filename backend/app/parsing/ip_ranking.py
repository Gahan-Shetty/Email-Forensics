"""IP candidate trust ranking.   OWNER: M2.

Produces -> response["ip_candidates"]  (sorted, index 0 = most credible)

This module is the intellectual core of the whole project.  It is the
difference between "we grabbed the first IP we saw" (what every other team
does) and "we ranked candidate IPs by how much we can trust whoever recorded
them" (defensible forensics).  API_CONTRACT.md section 3.4 is the spec.

The threat model, in one line: the sender controls every header they write, so
an IP is only as trustworthy as the server that OBSERVED and RECORDED it.
"""
from __future__ import annotations

from ..core.config import TRUSTED_RECEIVER_DOMAINS

IS_STUB = True   # <-- M2: set False when rank_ip_candidates is implemented

# Trust tiers and their base scores.  Tune these against real samples.
TIER_BASE_SCORE = {
    "provider_observed": 0.85,   # recorded by a receiver we trust to log honestly
    "transit_relay": 0.55,       # recorded by some other real MTA in the path
    "client_asserted": 0.25,     # only the sender's own headers claim it
    "unverifiable": 0.05,        # malformed / no corroboration
}


def is_trusted_receiver(hostname: str | None) -> bool:
    """Does this hostname belong to a provider we trust to log a sender IP?

    TODO(M2): lowercase, strip trailing dot, then check whether the hostname
    equals or ends with '.' + any entry in TRUSTED_RECEIVER_DOMAINS.
    Substring matching is WRONG here: 'google.com.evil.tld' must not match.
    Compare suffix-wise on label boundaries.

    The domain list lives in core/config.py because M3's confidence model reads
    the same list.  Add domains THERE, not here.
    """
    return False


def rank_ip_candidates(chain: list[dict], auth: dict) -> list[dict]:
    """MAIN ENTRY POINT for M2.  -> response["ip_candidates"]

    Inputs are M1's received_chain and your own authentication dict.

    TODO(M2) implementation order:
      1. Walk the chain from hop 1 (closest to sender) upward.  For every hop
         with a from_ip, build a candidate.
      2. EXCLUDE (excluded=True + exclusion_reason, but KEEP in the list so the
         UI can show the working):
           - is_private_ip           -> "RFC1918/private address, not routable"
           - duplicate of a candidate already seen at a lower hop_index
      3. Assign trust_tier:
           provider_observed  if is_trusted_receiver(hop["by_host"])
           transit_relay      elif hop["by_host"] looks like a real MTA
                              (has a dot, resolves-ish, not the same as from_host)
           client_asserted    elif this is the very first hop and by_host is
                              missing/unparseable
           unverifiable       else / parse_ok is False
      4. trust_score = TIER_BASE_SCORE[tier] with small adjustments:
           +0.05  hop has TLS
           +0.05  hop timestamp present and consistent with neighbours
           -0.10  auth["self_asserted_only"] is True
           -0.05  hop parse_ok is False
         Clamp to [0.0, 1.0].  Round to 2dp so the JSON stays readable.
      5. reasons: 1-3 short human sentences per candidate.  These get printed
         verbatim in the forensic report, so write them like an analyst would:
         "Recorded by Google receiving infrastructure", not "tier=0".
      6. SORT: non-excluded first, then trust_score DESC, then hop_index ASC.
         Ties broken by lower hop_index (closer to sender wins).

    Contract guarantee you must uphold: if any non-excluded candidate exists,
    it is at index 0.  M3 reads candidates[0] and trusts your ordering.

    Return [] when the chain has no usable IP at all.  M3 then produces the
    "no externally observed IP" origin - that path is tested, not an error.
    """
    return []
