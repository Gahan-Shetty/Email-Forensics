"""Confidence model + origin assembly.   OWNER: M3.

Produces -> response["origin"]  and  response["map_hops"]

This module is the project's credibility.  Every other team will put a pin on a
map and call it the attacker's location.  We put a pin on a map and say exactly
how much it is worth.  API_CONTRACT.md section 6 is the spec and the wording is
NOT paraphrasable - the report and the UI both use these exact strings.
"""
from __future__ import annotations

from ..core.config import TRUSTED_RECEIVER_DOMAINS  # noqa: F401  (used once implemented)
from .geoip import _empty_geo, classify_infrastructure, lookup_ip

IS_STUB = True   # <-- M3: set False when build_origin is implemented

# Verbatim from API_CONTRACT.md section 6.  Do not reword.
STATEMENT_TEMPLATE = (
    "Observed sending infrastructure is geolocated to {location}. This represents "
    "visible email-delivery infrastructure, not a verified physical location of "
    "the sender. Confidence: {confidence}."
)
NO_ORIGIN_STATEMENT = (
    "No externally observed sending IP could be recovered from this message's "
    "headers. Origin infrastructure could not be geolocated. Confidence: low."
)

# infrastructure types that can never yield "high" confidence, because the
# visible IP is by definition not the originating human's connection.
CONFIDENCE_CAPPED_INFRA = {"vpn", "tor", "hosting", "webmail_provider"}


def format_location(geo: dict) -> str:
    """'Singapore, SG' / 'Frankfurt, DE' / 'Germany' / 'an undetermined location'.

    TODO(M3): prefer 'city, country_code'; fall back to country; fall back to
    the literal string 'an undetermined location' (it reads correctly inside
    STATEMENT_TEMPLATE, which is why it is worded that way).
    """
    return "an undetermined location"


def assess_confidence(candidate: dict, geo: dict, auth: dict,
                      chain_integrity: dict) -> tuple[str, list[str]]:
    """-> ("high"|"medium"|"low", [human-readable reasons])

    TODO(M3) - implement as start-high-then-demote, it is much easier to reason
    about and to explain to a judge than accumulating points:

      start: level = "high", reasons = []

      demote to "medium" and append a reason when ANY of:
        candidate["trust_tier"] == "transit_relay"
        geo["is_datacenter"] or classify_infrastructure(...) == "hosting"
        auth spf and dkim are both not "pass"
        chain_integrity["gaps_suspected"]
        geo["lookup_source"] in {"geolite2", "cache"}   (weaker infra signals)

      demote to "low" and append a reason when ANY of:
        candidate["trust_tier"] in {"client_asserted", "unverifiable"}
        infrastructure_type in {"vpn", "tor"}
        infrastructure_type == "webmail_provider"
        geo["is_proxy"]
        geo["lookup_source"] == "unavailable"
        chain_integrity["malformed_hops"] > 0
        chain_integrity["backward_time_jumps"] > 0
        auth["self_asserted_only"]

      promote NEVER.  Only demote.

      If level is still "high", append the positive reason
      "IP was observed and recorded by a trusted receiving provider".

    Write the reasons the way an analyst writes a case note - full sentences,
    no jargon, because they are printed verbatim in the forensic PDF:
      GOOD: "Address belongs to datacenter/hosting infrastructure, which
             obscures the operator's own connection."
      BAD:  "is_datacenter=True"

    Always return at least one reason.  A confidence label with no stated
    justification is exactly the thing this project exists to avoid.
    """
    return "low", ["Confidence model not yet implemented (stub)."]


def build_origin(candidates: list[dict], auth: dict, chain_integrity: dict,
                 skip_geoip: bool = False) -> tuple[dict, list[dict]]:
    """MAIN ENTRY POINT.  -> (response["origin"], response["map_hops"])

    TODO(M3) implementation order:
      1. usable = [c for c in candidates if not c["excluded"]]
         if not usable  ->  return the no-origin origin (geo=_empty_geo(),
         confidence="low", statement=NO_ORIGIN_STATEMENT, reasons explaining
         why) and map_hops=[].   TEST THIS PATH FIRST - webmail-pasted emails
         hit it constantly and it must not crash the demo.
      2. best = usable[0]        # M2 guarantees the sort order; do not re-sort
      3. geo = _empty_geo() if skip_geoip else lookup_ip(best["ip"])
      4. infra = classify_infrastructure(geo, best.get("observed_by"))
      5. confidence, reasons = assess_confidence(best, geo, auth, chain_integrity)
      6. statement = STATEMENT_TEMPLATE.format(location=format_location(geo),
                                               confidence=confidence)
      7. map_hops: geolocate up to the top 5 usable candidates (they are cached,
         so this is cheap) and emit one entry per candidate that has lat AND
         lon.  Mark best's entry is_selected_origin=True.  Every entry carries
         its own confidence label - the contract forbids an unlabelled pin.
         Skip entirely when skip_geoip is True.

    Guarantees you must uphold:  confidence is never None and never outside the
    enum; statement is never empty.
    """
    origin = {
        "selected_ip": None,
        "selected_from_hop": None,
        "geo": _empty_geo(),
        "infrastructure_type": "unknown",
        "confidence": "low",
        "confidence_reasons": ["Origin module not yet implemented (stub)."],
        "statement": NO_ORIGIN_STATEMENT,
    }
    return origin, []
