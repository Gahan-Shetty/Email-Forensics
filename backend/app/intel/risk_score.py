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

IS_STUB = False  # <-- M3: set False when score_risk is implemented

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
    signals_output = []
    total_score = 0
    
    # 1. AUTH_FAIL
    spf = auth.get("spf", {}).get("result", "none")
    dkim = auth.get("dkim", {}).get("result", "none")
    dmarc = auth.get("dmarc", {}).get("result", "none")
    self_asserted = auth.get("self_asserted_only", False)
    auth_triggered = (dmarc == "fail") or (spf in {"fail", "softfail"}) or self_asserted
    auth_ev = f"spf={spf}, dkim={dkim}, dmarc={dmarc}" + (" (self-asserted only)" if self_asserted else "") if auth_triggered else None

    # 2. INFRA_FLAGGED
    infra_type = origin.get("infrastructure_type", "unknown")
    geo = origin.get("geo", {})
    infra_triggered = (infra_type in {"vpn", "tor", "hosting"}) or geo.get("is_proxy") or geo.get("is_datacenter")
    infra_ev = f"{geo.get('asn', '')} {geo.get('org', '')} - {infra_type}".strip() if infra_triggered else None

    # 3. REPLYTO_MISMATCH 
    mismatch_triggered = False
    mismatch_ev = None
    for anomaly in headers.get("anomalies", []):
        if anomaly.get("code") in {"REPLYTO_DOMAIN_MISMATCH", "RETURNPATH_DOMAIN_MISMATCH"}:
            mismatch_triggered = True
            mismatch_ev = anomaly.get("detail")
            break

    # 4. CHAIN_ANOMALY
    chain_issues = []
    if chain_integrity.get("backward_time_jumps", 0) > 0: chain_issues.append("backward time jumps")
    if chain_integrity.get("malformed_hops", 0) > 0: chain_issues.append("malformed hops")
    if chain_integrity.get("gaps_suspected"): chain_issues.append("gaps suspected")
    if chain_integrity.get("hop_count", 0) == 0: chain_issues.append("hop_count == 0")
    chain_triggered = len(chain_issues) > 0
    chain_ev = ", ".join(chain_issues) if chain_triggered else None

    # 5. URGENCY_KEYWORDS
    subject_and_body = (headers.get("subject", "") + " " + body_text).lower()
    found = [kw for kw in URGENCY_KEYWORDS if kw in subject_and_body]
    urgency_triggered = len(found) >= 2
    urgency_ev = f"matched: {', '.join([repr(k) for k in found])}" if urgency_triggered else None

    # Map to SIGNAL_DEFS to preserve the fixed order and weights
    evals = [
        (auth_triggered, auth_ev), 
        (infra_triggered, infra_ev), 
        (mismatch_triggered, mismatch_ev), 
        (chain_triggered, chain_ev), 
        (urgency_triggered, urgency_ev)
    ]
    
    for i, (code, label, points) in enumerate(SIGNAL_DEFS):
        trig, ev = evals[i]
        if trig:
            total_score += points
        signals_output.append({
            "code": code, 
            "label": label, 
            "points": points, 
            "triggered": trig, 
            "evidence": ev
        })

    final_score = max(0, min(total_score, 100))
    band = band_for(final_score)

    return {
        "score": final_score,
        "band": band,
        "verdict": VERDICT_BY_BAND[band],
        "signals": signals_output
    }
