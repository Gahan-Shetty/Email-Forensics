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

from ..core.config import (
    GEOIP_CACHE_TTL_SECONDS,
    GEOIP_PROVIDER,
    GEOIP_TIMEOUT_SECONDS,
    HOSTING_ORG_HINTS,
    TOR_ORG_HINTS,
    VPN_ORG_HINTS,
    WEBMAIL_PROVIDER_HINTS,
)

IS_STUB = True   # <-- M3: set False when lookup_ip is implemented

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
    """MAIN ENTRY POINT.  -> origin["geo"]

    TODO(M3) implementation order:
      1. cache check first  (_cache_get)
      2. if GEOIP_PROVIDER == "mock": return a fixed Singapore/DigitalOcean geo.
         Build this FIRST - it unblocks your confidence + scoring work and makes
         your unit tests deterministic and offline.
      3. ip-api path:
           requests.get(IP_API_URL.format(ip=ip),
                        params={"fields": IP_API_FIELDS},
                        timeout=GEOIP_TIMEOUT_SECONDS)
           if payload["status"] != "success": return _empty_geo() (+ warning)
           map:  countryCode->country_code, regionName->region, as->asn,
                 hosting->is_datacenter, proxy->is_proxy, mobile->is_mobile
           lookup_source = "ip-api.com"
      4. wrap EVERYTHING in try/except (requests.RequestException, ValueError,
         KeyError) -> fall through to geolite2, then to _empty_geo().
      5. _cache_put on success.

    Rate limit reality: ip-api free tier is 45 requests/minute and returns HTTP
    429 after that.  A single email has <10 hops, so you are fine for a demo -
    but the cache is what saves you during a 30-minute rehearsal loop.
    """
    cached = _cache_get(ip)
    if cached:
        return cached
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
    """-> one of the InfraType enum values (API_CONTRACT.md section 5).

    Order matters - check most specific first:
      tor               org/isp matches TOR_ORG_HINTS
      vpn               org/isp matches VPN_ORG_HINTS, or geo["is_proxy"]
      webmail_provider  hostname or org matches WEBMAIL_PROVIDER_HINTS
      hosting           geo["is_datacenter"], or org matches HOSTING_ORG_HINTS
      mobile_carrier    geo["is_mobile"]
      residential_isp   an ISP is present and none of the above matched
      unknown           no data at all

    TODO(M3): lowercase and concatenate isp+org+asn+hostname into one haystack,
    then substring-test each hint set.  Substring matching is acceptable here
    (unlike hostname trust checks) because we are classifying, not authorising.

    'hosting' is the single most important outcome to get right: it is what
    drives the medium/low confidence demo, since a rented VPS tells you where
    the server is and nothing about where the human is.
    """
    return "unknown"
