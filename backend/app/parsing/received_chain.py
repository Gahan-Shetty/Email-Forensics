"""Received-chain parsing and integrity.   OWNER: M1.

Produces -> response["received_chain"]  and  response["chain_integrity"]

+---------------------------------------------------------------------------+
| THE ONE THING TO GET RIGHT                                                |
|                                                                           |
| Mail servers PREPEND their Received header.  So in the raw source the      |
| TOP Received line is the LAST hop (nearest the recipient) and the BOTTOM   |
| Received line is the FIRST hop (nearest the sender).                       |
|                                                                           |
| Our contract says hop_index == 1 is CLOSEST TO THE SENDER.                 |
| So:  hops = list(reversed(all_received_headers))  then number from 1.      |
|                                                                           |
| Get this backwards and the entire trace, map, and origin selection is      |
| silently inverted while still looking plausible.  Write the test first.    |
+---------------------------------------------------------------------------+
"""
from __future__ import annotations

IS_STUB = True   # <-- M1: set False when both functions are implemented

# Regexes to start from.  Received headers are notoriously inconsistent -
# expect to iterate on these against real samples.
RE_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def is_private_ip(ip: str | None) -> bool:
    """True for RFC1918 / loopback / link-local / CGNAT / reserved.

    TODO(M1): use ipaddress.ip_address(ip) and check
    .is_private or .is_loopback or .is_link_local or .is_reserved
    plus CGNAT 100.64.0.0/10 explicitly (Python doesn't call it private).
    Return True on ValueError - an unparseable IP must never be treated as a
    usable public origin.
    """
    return True


def parse_one_hop(raw_hop: str, hop_index: int) -> dict:
    """Parse a single Received header value into the ReceivedHop shape.

    TODO(M1): pull out
        from_host  - hostname right after 'from '
        from_ip    - first public-looking IP in brackets/parens after 'from'
        by_host    - hostname right after 'by '
        protocol   - 'with (E)SMTPS?A?' token
        tls        - protocol contains 'S' (ESMTPS) or line mentions TLS/version=
        timestamp  - text after the LAST ';'  -> parsedate_to_datetime -> UTC Z
    Set parse_ok=False if you cannot find at least one of from_host/from_ip.
    NEVER raise - a malformed hop is data, not an error.
    """
    return {
        "hop_index": hop_index,
        "raw": raw_hop,
        "from_host": None,
        "from_ip": None,
        "by_host": None,
        "by_ip": None,
        "protocol": None,
        "tls": False,
        "timestamp": None,
        "timestamp_raw": None,
        "is_private_ip": True,
        "parse_ok": False,
    }


def parse_received_chain(raw_email: str) -> list[dict]:
    """MAIN ENTRY POINT.  -> response["received_chain"]

    TODO(M1):
      1. msg.get_all("Received") or []           # top-to-bottom = newest-to-oldest
      2. reverse it so index 0 == oldest == closest to sender
      3. parse_one_hop(raw, i+1) for each
    Return [] for a message with no Received headers (common for drafts and for
    pasted-from-webmail-UI text).  M2 handles the empty case.
    """
    return []


def assess_chain_integrity(chain: list[dict]) -> dict:
    """MAIN ENTRY POINT.  -> response["chain_integrity"]

    TODO(M1):
      hop_count            len(chain)
      timestamps_monotonic timestamps non-decreasing from hop 1 -> N
                           (ignore hops whose timestamp is None)
      backward_time_jumps  count of consecutive pairs where t[i+1] < t[i]
                           (allow ~60s of clock skew before counting it - real
                           mail servers disagree about the time constantly)
      largest_gap_seconds  max delta between consecutive timestamps
      gaps_suspected       hop[i].by_host does not match hop[i+1].from_host
                           -> a hop may have been removed
      malformed_hops       count of parse_ok == False
      notes                short human-readable strings for the UI
    M3 turns this into the CHAIN_ANOMALY risk signal, so keep the booleans
    honest rather than generous.
    """
    return {
        "hop_count": len(chain),
        "timestamps_monotonic": True,
        "backward_time_jumps": 0,
        "largest_gap_seconds": 0,
        "gaps_suspected": False,
        "malformed_hops": 0,
        "notes": [],
    }
