"""IP geolocation + infrastructure classification.   OWNER: M3.

Produces -> origin["geo"]  and  origin["infrastructure_type"]

Primary source: ip-api.com/json/{ip}  - free, no API key, 45 req/min per IP.
Backup: MaxMind GeoLite2 offline .mmdb (no city-level proxy flags, but works
with the venue wifi down, which WILL happen).

Non-negotiable for demo day: cache everything, and never let a network failure
break the request.  A geo lookup that fails returns lookup_source="unavailable"
and the pipeline continues with confidence forced to "low".
"""
from __future__ import annotations

import time
import requests

from ..core.config import (
    GEOIP_CACHE_TTL_SECONDS,
    GEOIP_PROVIDER,
    GEOIP_TIMEOUT_SECONDS,
    HOSTING_ORG_HINTS,
    TOR_ORG_HINTS,
    VPN_ORG_HINTS,
    WEBMAIL_PROVIDER_HINTS,
)

IS_STUB = False   # <-- M3: set False when lookup_ip is implemented

# ip-api free endpoint + the exact fields we want (fewer fields = faster).
IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,mobile"

# ip -> (expires_at_epoch, geo_dict).  Process-local, no DB needed for MVP.
_CACHE: dict[str, tuple[float, dict]] = {}


def _empty_geo() -> dict:
    return {
        "country": None, "country_code": None, "region": None, "city": None,
        "lat": None, "lon": None, "isp": None, "org": None, "asn": None,
        "is_datacenter": False, "is_proxy": False, "is_mobile": False,
        "lookup_source": "unavailable",
    }


def _cache_get(ip: str) -> dict | None:
    hit = _CACHE.get(ip)
    if hit and hit[0] > time.time():
        geo = dict(hit[1])
        geo["lookup_source"] = "cache"
        return geo
    return None


def _cache_put(ip: str, geo: dict) -> None:
    _CACHE[ip] = (time.time() + GEOIP_CACHE_TTL_SECONDS, dict(geo))


def lookup_ip(ip: str) -> dict:
    """MAIN ENTRY POINT.  -> origin["geo"]"""
    cached = _cache_get(ip)
    if cached:
        return cached

    if GEOIP_PROVIDER == "mock":
        geo = {
            "country": "Singapore",
            "country_code": "SG",
            "region": None,
            "city": None,
            "lat": None,
            "lon": None,
            "isp": "DigitalOcean",
            "org": "DigitalOcean",
            "asn": None,
            "is_datacenter": True,
            "is_proxy": False,
            "is_mobile": False,
            "lookup_source": "mock",
        }
        _cache_put(ip, geo)
        return geo

    # ACTUAL IMPLEMENTATION: Replaces the unconditional 'return _empty_geo()'
    try:
        response = requests.get(
            IP_API_URL.format(ip=ip),
            params={"fields": IP_API_FIELDS},
            timeout=GEOIP_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("status") != "success":
            return _empty_geo()

        # Map the ip-api fields to our internal contract
        geo = {
            "country": payload.get("country"),
            "country_code": payload.get("countryCode"),
            "region": payload.get("regionName"),
            "city": payload.get("city"),
            "lat": payload.get("lat"),
            "lon": payload.get("lon"),
            "isp": payload.get("isp"),
            "org": payload.get("org"),
            "asn": payload.get("as"),
            "is_datacenter": bool(payload.get("hosting")),
            "is_proxy": bool(payload.get("proxy")),
            "is_mobile": bool(payload.get("mobile")),
            "lookup_source": "ip-api.com",
        }
        _cache_put(ip, geo)
        return geo

    except Exception:
        # Fallback for timeouts, network disconnects, or API limit errors
        return _empty_geo()

def lookup_ip_geolite2(ip: str) -> dict:
    """Offline fallback.  -> origin["geo"] with lookup_source="geolite2"

    TODO(M3), only if time allows:
      * pip install geoip2, download GeoLite2-City.mmdb (free MaxMind account)
      * put it at the path in config.GEOLITE2_DB_PATH (it is .gitignored -
        4 MB binaries do not belong in the repo)
      * geoip2.database.Reader(path).city(ip)
    No proxy/hosting flags from this source, so set is_datacenter/is_proxy from
    the ORG NAME via classify_infrastructure instead.  Note that in the demo:
    offline mode gives us location but weaker infrastructure signals, so
    confidence drops.  That is honest behaviour, and saying so out loud lands
    well with judges.
    """
    return _empty_geo()


def classify_infrastructure(geo: dict, hostname: str | None = None) -> str:
    """Classify the visible IP infrastructure."""

    isp = str(geo.get("isp") or "").lower()
    org = str(geo.get("org") or "").lower()
    asn = str(geo.get("asn") or "").lower()
    host = str(hostname or "").lower()

    haystack = " ".join([isp, org, asn, host])

    # Most specific first.
    if any(str(hint).lower() in haystack for hint in TOR_ORG_HINTS):
        return "tor"

    if geo.get("is_proxy") or any(
        str(hint).lower() in haystack for hint in VPN_ORG_HINTS
    ):
        return "vpn"

    # Only treat the hostname as webmail evidence when it actually
    # matches a configured webmail provider hint.
    if any(str(hint).lower() in org for hint in WEBMAIL_PROVIDER_HINTS) and any(
        str(hint).lower() in host for hint in WEBMAIL_PROVIDER_HINTS
    ):
        return "webmail_provider"

    if geo.get("is_datacenter") or any(
        str(hint).lower() in haystack for hint in HOSTING_ORG_HINTS
    ):
        return "hosting"

    if geo.get("is_mobile"):
        return "mobile_carrier"

    if isp or org:
        return "residential_isp"

    return "unknown"