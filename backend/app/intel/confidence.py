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

IS_STUB = False  # <-- M3: set False when build_origin is implemented

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
    """'Singapore, SG' / 'Frankfurt, DE' / 'Germany' / 'an undetermined location'."""
    
    city = geo.get("city")
    country_code = geo.get("country_code")
    country = geo.get("country")

    if city and country_code:
        return f"{city}, {country_code}"

    if country:
        return country

    return "an undetermined location"


def assess_confidence(candidate: dict, geo: dict, auth: dict,
                      chain_integrity: dict) -> tuple[str, list[str]]:
    level = "high"
    reasons = []

    infra = classify_infrastructure(geo, candidate.get("observed_by"))

    # Medium confidence
    if candidate.get("trust_tier") == "transit_relay":
        level = "medium"
        reasons.append(
            "The IP was observed through a transit relay, which provides weaker evidence of the sender's original connection."
        )

    if geo.get("is_datacenter") or infra == "hosting":
        level = "medium"
        reasons.append(
            "Address belongs to datacenter/hosting infrastructure, which obscures the operator's own connection."
        )

    spf_result = auth.get("spf", {}).get("result")
    dkim_result = auth.get("dkim", {}).get("result")

    if spf_result != "pass" and dkim_result != "pass":
        level = "medium"
        reasons.append(
            "Neither SPF nor DKIM authentication passed, reducing confidence in the observed sending path."
        )

    if chain_integrity.get("gaps_suspected"):
        level = "medium"
        reasons.append(
            "Gaps were detected in the message delivery chain, reducing confidence in the observed path."
        )

    if geo.get("lookup_source") in {"geolite2", "cache"}:
        level = "medium"
        reasons.append(
            "Location data came from a source with weaker infrastructure signals."
        )

    # Low confidence
    if candidate.get("trust_tier") in {"client_asserted", "unverifiable"}:
        level = "low"
        reasons.append(
            "The IP is client-asserted or could not be independently verified."
        )

    if infra in {"vpn", "tor"}:
        level = "low"
        reasons.append(
            "The address belongs to VPN or Tor infrastructure, which obscures the original connection."
        )

    if infra == "webmail_provider":
        level = "low"
        reasons.append(
            "The address belongs to webmail infrastructure rather than a verified sender connection."
        )

    if geo.get("is_proxy"):
        level = "low"
        reasons.append(
            "The address is identified as a proxy, obscuring the original connection."
        )

    if chain_integrity.get("malformed_hops", 0) > 0:
        level = "low"
        reasons.append(
            "Malformed hops were detected in the delivery chain."
        )

    if chain_integrity.get("backward_time_jumps", 0) > 0:
        level = "low"
        reasons.append(
            "Backward timestamp jumps were detected in the delivery chain."
        )

    if auth.get("self_asserted_only"):
        level = "low"
        reasons.append(
            "Authentication evidence is self-asserted and was not independently confirmed."
        )

    if level == "high":
        reasons.append(
            "IP was observed and recorded by a trusted receiving provider"
        )

    return level, reasons


def build_origin(candidates: list[dict], auth: dict, chain_integrity: dict,
                 skip_geoip: bool = False) -> tuple[dict, list[dict]]:
    """Build the origin result and map hops."""

    usable = [c for c in candidates if not c.get("excluded", False)]

    # No usable candidates
    if not usable:
        origin = {
            "selected_ip": None,
            "selected_from_hop": None,
            "geo": _empty_geo(),
            "infrastructure_type": "unknown",
            "confidence": "low",
            "confidence_reasons": [
                "No externally observed sending IP could be recovered from this message's headers."
            ],
            "statement": NO_ORIGIN_STATEMENT,
        }
        return origin, []

    # M2 already sorts candidates by trust/quality.
    best = usable[0]

    # Geolocation
    geo = _empty_geo() if skip_geoip else lookup_ip(best["ip"])

    # Infrastructure classification
    infra = classify_infrastructure(
        geo,
        best.get("observed_by"),
    )

    # Confidence
    confidence, reasons = assess_confidence(
        best,
        geo,
        auth,
        chain_integrity,
    )

    # Human-readable statement
    statement = STATEMENT_TEMPLATE.format(
        location=format_location(geo),
        confidence=confidence,
    )

    origin = {
        "selected_ip": best.get("ip"),
        "selected_from_hop": best.get("hop_index"),
        "geo": geo,
        "infrastructure_type": infra,
        "confidence": confidence,
        "confidence_reasons": reasons,
        "statement": statement,
    }

    map_hops = []

    # GeoIP can be disabled for tests/offline mode.
    if not skip_geoip:
        for candidate in usable[:5]:
            candidate_geo = lookup_ip(candidate["ip"])

            if candidate_geo.get("lat") is None or candidate_geo.get("lon") is None:
                continue

            candidate_infra = classify_infrastructure(
                candidate_geo,
                candidate.get("observed_by"),
            )

            candidate_confidence, _ = assess_confidence(
                candidate,
                candidate_geo,
                auth,
                chain_integrity,
            )

            map_hops.append({
                "ip": candidate.get("ip"),
                "lat": candidate_geo["lat"],
                "lon": candidate_geo["lon"],
                "is_selected_origin": candidate.get("ip") == best.get("ip"),
                "confidence": candidate_confidence,
                "infrastructure_type": candidate_infra,
            })

    return origin, map_hops
