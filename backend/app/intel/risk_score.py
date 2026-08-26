"""Rule-based risk scoring.   OWNER: M3.

Produces -> response["risk"]

Deliberately NOT machine learning.  Two reasons, both worth saying to a judge:
  1. Two days.
  2. Explainability.  Every point on the score traces to a named rule with the
     exact evidence string that triggered it.  An analyst can defend this in a
     report; a model output they cannot inspect is much harder to act on.

Contract requirement: `signals` ALWAYS contains all 5 rules in the fixed order
below, triggered True or False.  The UI renders the untriggered ones greyed out,
which is how the user sees what was checked and passed - as valuable as what
failed.
"""
from __future__ import annotations

IS_STUB = True   # <-- M3: set False when score_risk is implemented

# Fixed order + weights.  Changing a weight is fine (tune against samples);
# changing a CODE is a contract change - see API_CONTRACT.md section 8.
SIGNAL_DEFS = [
    ("AUTH_FAIL",        "SPF/DKIM/DMARC failure",              30),
    ("INFRA_FLAGGED",    "VPN / proxy / hosting / datacenter",   25),
    ("REPLYTO_MISMATCH", "Reply-To domain != From domain",       20),
    ("CHAIN_ANOMALY",    "Broken or backward Received chain",    15),
    ("URGENCY_KEYWORDS", "Suspicious urgency language",          10),
]

BAND_THRESHOLDS = [(75, "critical"), (50, "high"), (25, "medium"), (0, "low")]

VERDICT_BY_BAND = {
    "critical": "likely_phishing",
    "high": "suspicious",
    "medium": "inconclusive",
    "low": "likely_legitimate",
}

# Keep this list short and defensible.  A 200-word keyword list produces false
# positives on ordinary business mail and someone will ask you about it.
URGENCY_KEYWORDS = [
    "verify your account", "suspended", "within 24 hours", "immediate action",
    "click here", "confirm your identity", "unusual activity", "account locked",
    "final warning", "update your payment", "wire transfer", "urgent",
    "act now", "your password will expire", "unauthorized login",
]


def band_for(score: int) -> str:
    for threshold, name in BAND_THRESHOLDS:
        if score >= threshold:
            return name
    return "low"


def score_risk(headers: dict, auth: dict, origin: dict,
               chain_integrity: dict, body_text: str) -> dict:
    """MAIN ENTRY POINT.  -> response["risk"]

    TODO(M3) - build each signal as (triggered: bool, evidence: str | None):

      AUTH_FAIL (+30)
        trigger: dmarc.result == "fail"  OR  spf.result in {"fail","softfail"}
                 OR  auth["self_asserted_only"] is True
        evidence: f"spf={spf.result}, dkim={dkim.result}, dmarc={dmarc.result}"
                  and append " (self-asserted only)" when applicable

      INFRA_FLAGGED (+25)
        trigger: origin["infrastructure_type"] in {"vpn","tor","hosting"}
                 OR origin["geo"]["is_proxy"] OR origin["geo"]["is_datacenter"]
        evidence: f"{geo['asn']} {geo['org']} - {infrastructure_type}"

      REPLYTO_MISMATCH (+20)
        trigger: any anomaly in headers["anomalies"] with code
                 REPLYTO_DOMAIN_MISMATCH or RETURNPATH_DOMAIN_MISMATCH
        evidence: that anomaly's detail string
        NOTE: read M1's anomalies, do NOT recompute the domain comparison here.
        One source of truth per fact.

      CHAIN_ANOMALY (+15)
        trigger: chain_integrity: backward_time_jumps > 0 OR malformed_hops > 0
                 OR gaps_suspected OR hop_count == 0
        evidence: short summary of which of those fired

      URGENCY_KEYWORDS (+10)
        trigger: >= 2 distinct keywords across subject + body_text (lowercased).
                 Require TWO, not one - "urgent" alone appears in plenty of
                 legitimate mail and single-keyword matching makes the whole
                 score look unserious.
        evidence: "matched: 'suspended', 'within 24 hours'"

    Then:
      score = sum(points for triggered), clamp 0..100
      band = band_for(score)
      verdict = VERDICT_BY_BAND[band]
      signals = ALL FIVE, in SIGNAL_DEFS order

    Never raise.  Missing input -> that signal is simply not triggered.
    """
    return {
        "score": 0,
        "band": "low",
        "verdict": "inconclusive",
        "signals": [
            {"code": c, "label": l, "points": p, "triggered": False, "evidence": None}
            for c, l, p in SIGNAL_DEFS
        ],
    }
