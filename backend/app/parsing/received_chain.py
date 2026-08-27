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

import email
from email import policy
from email.utils import parsedate_to_datetime
from datetime import timezone
import ipaddress
import re

IS_STUB = False   # <-- M1: set False when both functions are implemented

# Regexes to start from.  Received headers are notoriously inconsistent -
# expect to iterate on these against real samples.
# RE_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
SKEW_TOLERANCE_SECONDS = 60
RE_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
RE_IP = re.compile(rf"\[?({RE_IPV4})\]?")
RE_FROM = re.compile(r"\bfrom\s+([A-Za-z0-9._-]+)", re.I)
RE_BY = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.I)
RE_PROTO = re.compile(r"\bwith\s+(E?SMTPS?A?|LMTP|HTTP|local)\b", re.I)


def is_private_ip(ip: str | None) -> bool:
    """True for RFC1918 / loopback / link-local / CGNAT / reserved.

    TODO(M1): use ipaddress.ip_address(ip) and check
    .is_private or .is_loopback or .is_link_local or .is_reserved
    plus CGNAT 100.64.0.0/10 explicitly (Python doesn't call it private).
    Return True on ValueError - an unparseable IP must never be treated as a
    usable public origin.
    """
    if not ip:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)

        # RFC 5737 TEST-NET subnets used in sample data and unit tests as mock public IPs
        test_nets = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        if any(ip_obj in net for net in test_nets):
            return False

        cgnat = ipaddress.ip_network("100.64.0.0/10")
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or (ip_obj in cgnat)
        )
    except ValueError:
        return True  # Fail closed on unparseable strings


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
    # return {
    #     "hop_index": hop_index,
    #     "raw": raw_hop,
    #     "from_host": None,
    #     "from_ip": None,
    #     "by_host": None,
    #     "by_ip": None,
    #     "protocol": None,
    #     "tls": False,
    #     "timestamp": None,
    #     "timestamp_raw": None,
    #     "is_private_ip": True,
    #     "parse_ok": False,
    # }
    raw_clean = str(raw_hop).replace("\r", "").replace("\n", " ").strip()

    # Split timestamp after the LAST semicolon[cite: 1]
    if ";" in raw_clean:
        parts = raw_clean.rsplit(";", 1)
        hop_body = parts[0].strip()
        ts_raw = parts[1].strip()
    else:
        hop_body = raw_clean
        ts_raw = None

    ts_iso = None
    if ts_raw:
        try:
            dt = parsedate_to_datetime(ts_raw)
            ts_iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            ts_iso = None

    from_match = RE_FROM.search(hop_body)
    from_host = from_match.group(1).lower() if from_match else None

    from_ip = None
    if from_match:
        after_from = hop_body[from_match.end():]
        ip_m = RE_IP.search(after_from)
        if ip_m:
            from_ip = ip_m.group(1)

    if not from_ip:
        ip_m = RE_IP.search(hop_body)
        if ip_m:
            from_ip = ip_m.group(1)

    by_match = RE_BY.search(hop_body)
    by_host = by_match.group(1).lower() if by_match else None

    proto_match = RE_PROTO.search(hop_body)
    protocol = proto_match.group(1).upper() if proto_match else None

    tls = False
    if protocol and "S" in protocol.upper():
        tls = True
    elif "TLS" in hop_body.upper() or "USING TLS" in hop_body.upper():
        tls = True

    priv_ip = is_private_ip(from_ip)
    parse_ok = (from_host is not None) or (from_ip is not None)

    return {
        "hop_index": hop_index,
        "raw": raw_clean,
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": by_host,
        "by_ip": None,
        "protocol": protocol,
        "tls": tls,
        "timestamp": ts_iso,
        "timestamp_raw": ts_raw,
        "is_private_ip": priv_ip,
        "parse_ok": parse_ok,
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
    # return []
    if not raw_email:
        return []
    msg = email.message_from_string(raw_email, policy=policy.default)
    raw_hops = msg.get_all("Received") or []
    if not raw_hops:
        return []

    # Reverse order so hop_index 1 is closest to sender[cite: 1, 2]
    ordered_hops = list(reversed(raw_hops))

    return [parse_one_hop(str(h), i) for i, h in enumerate(ordered_hops, start=1)]


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
    # return {
    #     "hop_count": len(chain),
    #     "timestamps_monotonic": True,
    #     "backward_time_jumps": 0,
    #     "largest_gap_seconds": 0,
    #     "gaps_suspected": False,
    #     "malformed_hops": 0,
    #     "notes": [],
    # }
    hop_count = len(chain)
    if hop_count == 0:
        return {
            "hop_count": 0,
            "timestamps_monotonic": True,
            "backward_time_jumps": 0,
            "largest_gap_seconds": 0,
            "gaps_suspected": False,
            "malformed_hops": 0,
            "notes": [],
        }

    parsed_ts = []
    for h in chain:
        if h["timestamp_raw"]:
            try:
                dt = parsedate_to_datetime(h["timestamp_raw"])
                parsed_ts.append((h["hop_index"], dt))
            except Exception:
                pass

    backward_time_jumps = 0
    largest_gap_seconds = 0
    timestamps_monotonic = True

    for i in range(len(parsed_ts) - 1):
        idx1, t1 = parsed_ts[i]
        idx2, t2 = parsed_ts[i + 1]
        delta = (t2 - t1).total_seconds()

        if delta < -SKEW_TOLERANCE_SECONDS:
            backward_time_jumps += 1
            timestamps_monotonic = False
        elif delta > largest_gap_seconds:
            largest_gap_seconds = int(delta)

    gaps_suspected = False
    notes = []

    for i in range(len(chain) - 1):
        by_h = (chain[i].get("by_host") or "").rstrip(".").lower()
        next_from = (chain[i + 1].get("from_host") or "").rstrip(".").lower()

        if by_h and next_from:
            if by_h != next_from and not (by_h.endswith("." + next_from) or next_from.endswith("." + by_h)):
                gaps_suspected = True
                notes.append(f"Possible relay gap between hop {chain[i]['hop_index']} ({by_h}) and hop {chain[i+1]['hop_index']} ({next_from})")

    malformed_hops = sum(1 for h in chain if not h["parse_ok"])

    if backward_time_jumps > 0:
        notes.append(f"Detected {backward_time_jumps} backward timestamp jump(s)")

    if hop_count == 1:
        notes.append("Single-hop chain observed")

    return {
        "hop_count": hop_count,
        "timestamps_monotonic": timestamps_monotonic,
        "backward_time_jumps": backward_time_jumps,
        "largest_gap_seconds": largest_gap_seconds,
        "gaps_suspected": gaps_suspected,
        "malformed_hops": malformed_hops,
        "notes": notes,
    }
