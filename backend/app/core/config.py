"""Central config.  OWNER: M6 (Integration).  Do not edit if you are not M6.

Every value has a working default, so the app runs with no .env file at all.
"""
from __future__ import annotations

import os
from pathlib import Path

# repo root = .../sih26106-email-forensics
ROOT = Path(__file__).resolve().parents[3]

SCHEMA_VERSION = "1.0"


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, str(default)).strip().lower() in {"1", "true", "yes", "on"}


# --- geolocation (M3 reads these) -------------------------------------------
GEOIP_PROVIDER = _env("GEOIP_PROVIDER", "ip-api")          # ip-api | geolite2 | mock
GEOIP_TIMEOUT_SECONDS = _int("GEOIP_TIMEOUT_SECONDS", 4)
GEOIP_CACHE_TTL_SECONDS = _int("GEOIP_CACHE_TTL_SECONDS", 3600)
GEOLITE2_DB_PATH = ROOT / _env("GEOLITE2_DB_PATH", "backend/app/data/GeoLite2-City.mmdb")

# --- reporting (M4 reads these) --------------------------------------------
REPORT_OUTPUT_DIR = ROOT / _env("REPORT_OUTPUT_DIR", "evidence")
CUSTODY_LOG_PATH = ROOT / _env("CUSTODY_LOG_PATH", "evidence/custody_log.jsonl")

# --- api -------------------------------------------------------------------
MAX_UPLOAD_BYTES = _int("MAX_UPLOAD_BYTES", 2_000_000)
ALLOW_ORIGINS = [o.strip() for o in _env("ALLOW_ORIGINS", "*").split(",") if o.strip()]
ALLOWED_EXTENSIONS = {".eml", ".txt", ".msg"}
DEMO_MODE = _bool("DEMO_MODE", False)

FIXTURE_PATH = ROOT / "fixtures" / "sample_response.json"
SAMPLES_DIR = ROOT / "samples"

REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# Receiving providers we trust to log a sender IP honestly.  Used by M2's
# is_trusted_receiver() and by M3's confidence model.  Shared on purpose: both
# modules must agree on what "trusted" means or the confidence label is
# incoherent.  Add domains here, not in your own module.
TRUSTED_RECEIVER_DOMAINS = {
    "google.com", "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "protection.outlook.com",
    "protonmail.ch", "proton.me",
    "yahoodns.net", "yahoo.com",
    "zoho.com", "zohomail.com",
    "icloud.com", "me.com", "apple.com",
    "amazonses.com", "amazonaws.com",
    "mimecast.com", "pphosted.com", "messagelabs.com",
}

# Webmail / ESP sending infra: presence means the true origin IP is usually
# invisible, which caps confidence at "low"/"medium".
WEBMAIL_PROVIDER_HINTS = {
    "google", "gmail", "outlook", "hotmail", "microsoft", "proton",
    "yahoo", "zoho", "icloud", "aol", "yandex", "mail.ru", "gmx",
}

# ASN/org substrings that indicate datacenter or anonymisation infrastructure.
HOSTING_ORG_HINTS = {
    "amazon", "aws", "digitalocean", "linode", "akamai", "cloudflare",
    "google cloud", "gcp", "azure", "microsoft corporation", "ovh", "hetzner",
    "vultr", "contabo", "scaleway", "oracle cloud", "alibaba", "tencent",
    "leaseweb", "choopa", "colocrossing", "hostinger", "godaddy", "namecheap",
}
VPN_ORG_HINTS = {
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "mullvad", "private internet access",
    "cyberghost", "ipvanish", "hidemyass", "purevpn", "windscribe", "tunnelbear", "vpn",
}
TOR_ORG_HINTS = {"tor exit", "torservers", "tor-exit", "torproject"}
