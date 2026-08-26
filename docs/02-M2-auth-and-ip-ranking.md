# M2 — Authentication checks & IP trust ranking

You own the intellectual core of the project. Every other team at the hackathon
will grab the first IP in the header chain and put it on a map. You are building
the part that asks *who recorded this IP, and can we trust them?* — which is the
difference between a toy and something a cybercrime cell would recognise as
forensics.

**Read first:** `API_CONTRACT.md` §3 (`authentication`, `ip_candidates`), §3.4
(the ranking requirement), §5 (enums), §7 (your signatures).

---

## Your files

```
backend/app/parsing/auth_checks.py       evaluate_authentication()
backend/app/parsing/ip_ranking.py        rank_ip_candidates(), is_trusted_receiver()
backend/tests/test_m2_auth_ranking.py    your tests
```

**Never open:** `header_parser.py` or `received_chain.py` (M1's — you *read* their
output, you don't touch their code), anything in `intel/`, `report/`, `frontend/`.

## What you produce

| Function | Fills | Consumed by |
|---|---|---|
| `evaluate_authentication()` | `response["authentication"]` | M3 (confidence + `AUTH_FAIL`), M4 (report), M5 (badges) |
| `rank_ip_candidates()` | `response["ip_candidates"]` | M3 reads `candidates[0]` and **trusts your sort order** |

---

## The threat model, in one paragraph

A sender controls every byte of every header they write. They can write
`Authentication-Results: spf=pass`. They can write a fake `Received` header
claiming the message came from `mail.paypal.com`. What they **cannot** do is
control what the *receiving* server writes when it accepts the connection —
because that server observed the actual TCP source address.

So: an IP is exactly as trustworthy as the server that recorded it. That single
idea is your whole module, and it is the thing to say out loud in the demo.

---

## Part 1 — `evaluate_authentication()`

### Scope decision, and how to defend it

We **read** the `Authentication-Results` header that the receiving provider
wrote at delivery time. We do **not** perform live DNS SPF evaluation ourselves.

If a judge asks why: a result recorded by Gmail's inbound MTA at the moment of
delivery is stronger evidence than a result we recompute days later against DNS
that may have changed since. Re-evaluating SPF now tells you about today's DNS,
not about the delivery. That is not a shortcut — it is the correct forensic
posture, and re-querying would actively weaken the evidence.

### The header format

```
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of bounce@sendgrid.net does not designate
        203.0.113.9 as permitted sender) smtp.mailfrom=bounce@sendgrid.net;
    dkim=pass header.i=@example.com header.s=selector1;
    dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypa1-secure.tld
```

Parse it as: authserv-id before the first `;`, then each subsequent
`;`-delimited chunk starts with `mech=result`.

Pull out `smtp.mailfrom=` / `header.d=` / `header.i=` for the domain, `header.s=`
for the DKIM selector, and `p=REJECT|QUARANTINE|NONE` for the DMARC policy.
Keep the untouched substring in `raw` — the forensic PDF prints it verbatim.

### The bit that matters most: `verified_by` and `self_asserted_only`

There can be several `Authentication-Results` headers. Each one's authserv-id
says who made the claim.

```python
for header in all_auth_results_headers:
    authserv = header.split(";")[0].strip()
    if is_trusted_receiver(authserv):
        # trust this one. verified_by = authserv
        break
else:
    # no trusted header exists.
    # STILL report the results, but:
    #   verified_by = None
    #   self_asserted_only = True
```

`self_asserted_only = True` means: *this message claims its authentication
passed, and nobody trustworthy agrees.* It is one of the strongest signals the
tool produces, and it is a genuinely great ten seconds of demo — the email says
`spf=pass`, and your dashboard says "self-asserted; no trusted receiver
confirmed this."

### DKIM presence ≠ DKIM valid

A `DKIM-Signature` header being *present* tells you a signature exists. It does
not tell you it verifies. Extract `d=` and `s=` from it so the report can show
the claimed signing domain, but leave `result` as `"none"` unless a trusted
`Authentication-Results` says `dkim=pass`. Do not let a present-but-unverified
signature read as a pass.

### Alignment

```
spf_aligned  = spf.result == "pass"  and spf.domain  == from_domain
dkim_aligned = dkim.result == "pass" and dkim.domain == from_domain
from_vs_returnpath_match = return_path.domain == from.domain
```

Read `from_domain` from **M1's `headers` dict** — `headers["from"]["domain"]`.
Do not re-parse the `From` header yourself. Two implementations of the same
parse will drift apart and produce contradictory output in the same response.

Exact domain matching is an acceptable MVP simplification (real DMARC relaxed
mode aligns `mail.paypal.com` with `paypal.com` via the registrable domain). Just
know that it is a simplification, and say so if asked rather than being caught
by it.

---

## Part 2 — `rank_ip_candidates()`

### `is_trusted_receiver()` — get the matching right

```python
def is_trusted_receiver(hostname):
    if not hostname:
        return False
    h = hostname.strip().rstrip(".").lower()
    return any(h == d or h.endswith("." + d) for d in TRUSTED_RECEIVER_DOMAINS)
```

**Substring matching is a security bug here.** `"google.com" in
"google.com.evil.tld"` is `True`, and an attacker who names their relay
`google.com.evil.tld` would get promoted to `provider_observed`. Match on label
boundaries only. There is already a test for exactly this attack in your test
file.

The domain list lives in `core/config.py::TRUSTED_RECEIVER_DOMAINS` because M3's
confidence model reads the same list. Add domains **there**, not in your module —
if the two disagree about what "trusted" means, the confidence label becomes
incoherent.

### The four trust tiers

| Tier | Base | When |
|---|---|---|
| `provider_observed` | 0.85 | `is_trusted_receiver(hop["by_host"])` — a provider we trust wrote this down |
| `transit_relay` | 0.55 | `by_host` is some other real MTA (has a dot, differs from `from_host`) |
| `client_asserted` | 0.25 | first hop, `by_host` missing or unparseable — only the sender's own claim |
| `unverifiable` | 0.05 | `parse_ok` is False, or nothing corroborates it |

Adjustments, then clamp to `[0, 1]` and round to 2dp:

```
+0.05  hop has TLS
+0.05  timestamp present and consistent with neighbours
-0.10  auth["self_asserted_only"]
-0.05  parse_ok is False
```

### Exclusions — keep them in the list

```python
if hop["is_private_ip"]:
    excluded = True
    exclusion_reason = "RFC1918 private address, not externally routable"
```

Also exclude duplicates of an IP already seen at a lower `hop_index`.

**Keep excluded candidates in the returned list** with `excluded: True`. Do not
filter them out. M5's UI shows them greyed with the reason, and "here is what we
rejected and why" is far more persuasive to a judge than a single unexplained
answer. Showing the working is the product.

### Sort order — M3 depends on this

```python
candidates.sort(key=lambda c: (c["excluded"], -c["trust_score"], c["hop_index"]))
```

Non-excluded first, then highest trust, then closest to sender. **Contract
guarantee: if any non-excluded candidate exists, it is at index 0.** M3 reads
`candidates[0]` and does not re-sort.

### `reasons` are printed verbatim in a legal-ish document

Write them the way an analyst writes a case note:

> Good: `"Recorded by Google receiving infrastructure, which we treat as a
> trusted observer."`
>
> Bad: `"tier=provider_observed score=0.86"`

One to three short sentences per candidate.

---

## Build order

1. **Hour 1** — `is_trusted_receiver()` + its tests. Twenty minutes, unblocks
   everything else, and the suffix-spoofing test is a nice early win.
2. **Hour 2–3** — `parse_authentication_results()` against samples 01, 02, 03.
3. **Hour 4** — `verified_by` / `self_asserted_only` selection logic.
4. **Hour 5–6** — `rank_ip_candidates()` tiers, exclusions, sort.
5. **Evening** — alignment, DKIM `d=`/`s=` extraction, edge cases.

You are not blocked on M1: your test file already contains hand-written hop
dicts in the contract's shape. Code against those, and swap to real parser
output when M1 lands.

## Definition of done

- [ ] `python -m pytest backend/tests/test_m2_auth_ranking.py -q` green
- [ ] Sample 02 → `spf=fail`, `dmarc=fail`, `policy=reject`, `verified_by="mx.google.com"`
- [ ] Sample 01 → `spf=pass`, `dkim=pass`, `spf_aligned=True`
- [ ] Sample 06 (no auth headers) → all `"none"`, `verified_by=None`, no exception
- [ ] `is_trusted_receiver("google.com.evil.tld")` is `False`
- [ ] Sample 02 → `candidates[0]["ip"] == "203.0.113.9"`, tier `provider_observed`
- [ ] `10.20.30.40` present in the list with `excluded=True`
- [ ] Empty chain → `[]`
- [ ] `IS_STUB = False` in both files

## Traps

**Multiple `Authentication-Results` headers.** Common with forwarding. Iterate
all of them; pick the trusted one; do not just take the first.

**`Received-SPF` is a separate header.** Older providers use it instead. Read it
as a fallback when `Authentication-Results` has no `spf=`.

**ARC headers.** `ARC-Authentication-Results` preserves auth results across
forwarding hops. Populating `arc` is a bonus, not required — but if you see
`arc=pass` on a message where SPF fails, that is a forwarded message rather than
a spoof, and it is a genuinely sophisticated point to be able to make.

**Do not recompute what M1 already computed.** Domain comparisons for the
`Reply-To` mismatch live in M1's `anomalies`. M3 reads them from there. If you
also compute them, there are two sources of truth for one fact.
