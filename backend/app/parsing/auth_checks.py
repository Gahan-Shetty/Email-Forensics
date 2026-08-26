"""SPF / DKIM / DMARC / ARC evaluation.   OWNER: M2.

Produces -> response["authentication"]

Scope discipline for the MVP: we READ what the receiving provider already
verified (the Authentication-Results header), we do not perform live DNS SPF
evaluation ourselves.  That is the correct forensic posture anyway - a result
recorded by Gmail's inbound MTA at delivery time is stronger evidence than a
result we recompute days later against DNS that may have changed.

The important nuance, which is also a demo talking point:
  a sender can WRITE their own "Authentication-Results: spf=pass" header.
  Only the header written by the TRUSTED RECEIVER counts.  Track that in
  `verified_by` and `self_asserted_only`.
"""
from __future__ import annotations

IS_STUB = True   # <-- M2: set False when evaluate_authentication is implemented

VALID_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def _empty_mechanism() -> dict:
    return {"result": "none", "domain": None, "selector": None,
            "policy": None, "raw": None, "source": None}


def normalise_result(token: str | None) -> str:
    """Map a raw token to the frozen enum.  Unknown -> 'none'.

    TODO(M2): lowercase, strip punctuation.  Watch for 'hardfail' -> 'fail',
    'soft_fail' -> 'softfail', 'bestguesspass' -> 'neutral'.
    """
    if not token:
        return "none"
    t = token.strip().lower()
    return t if t in VALID_RESULTS else "none"


def parse_authentication_results(raw_value: str) -> dict:
    """Parse ONE Authentication-Results header into {mech: {...}}.

    Format:  <authserv-id>; spf=pass smtp.mailfrom=x.com; dkim=fail header.d=y.com; dmarc=pass (p=NONE)

    TODO(M2):
      * authserv-id = text before the first ';'  -> this is your `source`
      * split the rest on ';' then read the leading `mech=result` of each part
      * pull smtp.mailfrom= / header.d= / header.i= for the domain
      * pull header.s= for the DKIM selector
      * pull p=REJECT|QUARANTINE|NONE (often inside parens) for dmarc policy
      * keep the untouched substring in `raw` - the forensic report prints it
    """
    return {}


def evaluate_authentication(raw_email: str, headers: dict) -> dict:
    """MAIN ENTRY POINT for M2.  -> response["authentication"]

    `headers` is M1's output dict - read headers["from"]["domain"] and
    headers["return_path"]["domain"] from it.  Do NOT re-parse the From header
    yourself; that duplicates M1's logic and the two will drift apart.

    TODO(M2) implementation order:
      1. Collect ALL Authentication-Results headers (there can be several).
         Also read Received-SPF, DKIM-Signature, ARC-Authentication-Results.
      2. Choose which one to trust:
           for each header, its authserv-id is the host that made the claim.
           if is_trusted_receiver(authserv_id) -> use it, set verified_by=that host
           if NO trusted header exists but an untrusted one does ->
               still report the results BUT set self_asserted_only = True
               and verified_by = None.   This is a headline demo moment: the
               email claims spf=pass and we show that nobody trustworthy said so.
      3. DKIM-Signature presence: extract d= (domain) and s= (selector) even
         when there is no Authentication-Results - result stays "none" because
         a signature being PRESENT is not the same as it VERIFYING.
      4. alignment:
           spf_aligned   = spf.result=="pass"  and spf.domain  == from_domain
           dkim_aligned  = dkim.result=="pass" and dkim.domain == from_domain
           from_vs_returnpath_match = return_path.domain == from.domain
           envelope_from_domain = return_path.domain (or smtp.mailfrom)
         Use registrable-domain comparison if you have time (mail.paypal.com
         aligns with paypal.com under DMARC relaxed mode); exact match is an
         acceptable MVP simplification - just say so in the demo.

    Never raise.  A message with zero auth headers is a completely normal input
    and must return all-"none" plus self_asserted_only=False.
    """
    return {
        "spf": _empty_mechanism(),
        "dkim": _empty_mechanism(),
        "dmarc": _empty_mechanism(),
        "arc": _empty_mechanism(),
        "alignment": {
            "spf_aligned": False,
            "dkim_aligned": False,
            "from_vs_returnpath_match": False,
            "envelope_from_domain": None,
        },
        "verified_by": None,
        "self_asserted_only": False,
    }
