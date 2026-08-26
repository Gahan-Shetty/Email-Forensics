# M3 — Geolocation, confidence model & risk scoring

You own the project's credibility. The confidence model is the single feature
that separates this from every other header-analyzer at the event: everyone else
will put a pin on a map and imply it is the attacker. You put a pin on a map and
state precisely what it is worth.

**Read first:** `API_CONTRACT.md` §3 (`origin`, `map_hops`, `risk`), **§6 in
full** (the confidence rules and the required wording — this is a spec, not
guidance), §5 (enums), §7 (your signatures).

---

## Your files

```
backend/app/intel/geoip.py         lookup_ip(), classify_infrastructure()
backend/app/intel/confidence.py    assess_confidence(), build_origin(), format_location()
backend/app/intel/risk_score.py    score_risk(), band_for()
backend/tests/test_m3_intel.py     your tests
```

**Never open:** anything in `parsing/` (M1/M2's — you read their dicts),
anything in `report/`, `frontend/`, `schemas.py`, `pipeline.py`.

## What you produce

| Function | Fills | Consumed by |
|---|---|---|
| `build_origin()` | `response["origin"]`, `response["map_hops"]` | M4 (report prints the statement verbatim), M5 (origin card + map) |
| `score_risk()` | `response["risk"]` | M4, M5 |

---

## The core principle: only demote, never promote

Implement confidence as **start at `high`, demote on evidence of uncertainty.**

Do not accumulate points toward a confidence level. Demotion is easier to reason
about, easier to test, and — the reason that actually matters — easy to explain
to a judge: *"we begin by assuming the observation is good, then we list every
reason it might not be, and the worst one wins."*

```python
level = "high"
reasons = []

# --- demote to medium ---
if candidate["trust_tier"] == "transit_relay": demote("medium", "...")
if geo["is_datacenter"] or infra == "hosting": demote("medium", "...")
if spf != "pass" and dkim != "pass":           demote("medium", "...")
if chain_integrity["gaps_suspected"]:          demote("medium", "...")
if geo["lookup_source"] in {"geolite2","cache"}: demote("medium", "...")

# --- demote to low ---
if candidate["trust_tier"] in {"client_asserted","unverifiable"}: demote("low", "...")
if infra in {"vpn","tor","webmail_provider"}:  demote("low", "...")
if geo["is_proxy"]:                            demote("low", "...")
if geo["lookup_source"] == "unavailable":      demote("low", "...")
if chain_integrity["malformed_hops"] > 0:      demote("low", "...")
if chain_integrity["backward_time_jumps"] > 0: demote("low", "...")
if auth["self_asserted_only"]:                 demote("low", "...")
```

`demote()` only ever moves downward — `high → medium → low`, never back up. A
message with perfect authentication and a malformed routing chain is **low**
confidence. Good auth does not rescue a broken chain, because they are evidence
about different things: auth tells you about domain control, the chain tells you
about the route.

### The case that catches naive implementations

`samples/04_webmail_no_origin_ip.eml`: SPF passes, DKIM passes, DMARC passes,
sent from Gmail. A scorer keyed on authentication calls it clean and high
confidence.

But the only IP in the headers is Google's outbound relay. We know nothing about
where the sender was. Correct output: `infrastructure_type =
webmail_provider`, confidence **low**, and a statement that makes clear we are
looking at provider infrastructure.

If your build reports `high` on sample 04, the model is wrong. There is a test
for it: `test_webmail_forces_low_even_when_all_auth_passes`.

---

## The wording is not paraphrasable

```python
STATEMENT_TEMPLATE = (
    "Observed sending infrastructure is geolocated to {location}. This represents "
    "visible email-delivery infrastructure, not a verified physical location of "
    "the sender. Confidence: {confidence}."
)
```

Already in your file. **Do not reword it, do not shorten it, do not drop the
caveat sentence to make the UI tidier.** M4's report prints it verbatim, M5's UI
prints it verbatim, and there is a test asserting the caveat clause is present.
The whole "defensible forensics, not false certainty" pitch collapses if this
string gets casually edited at 3am.

`format_location()` falls back to the literal string `"an undetermined
location"` — worded that way so it reads correctly inside the template.

When there is no usable IP, use `NO_ORIGIN_STATEMENT` exactly as written.

---

## Build order — mock first, always

### Hour 1 — the mock geo path

```python
if GEOIP_PROVIDER == "mock":
    return {"country": "Singapore", "country_code": "SG", ...
            "org": "DigitalOcean", "is_datacenter": True,
            "lookup_source": "mock"}
```

Do this **before** touching the network. It makes every downstream test
deterministic and offline, and it means your confidence and scoring work is
never blocked by wifi, rate limits, or `requests` not being installed yet.

Then `export GEOIP_PROVIDER=mock` for all your local test runs.

### Hour 2 — `classify_infrastructure()`

Order matters, most specific first: `tor` → `vpn` → `webmail_provider` →
`hosting` → `mobile_carrier` → `residential_isp` → `unknown`.

Lowercase and concatenate `isp + org + asn + hostname` into one haystack, then
substring-test each hint set from `config.py`. Substring matching is fine here
(unlike M2's hostname trust check) because you are classifying, not authorising.

`hosting` is the highest-value outcome to get right — it is what drives the
medium-confidence demo path, since a rented VPS tells you where the server is and
nothing about where the human is.

### Hour 3–4 — `assess_confidence()` and `build_origin()`

Test the **no-candidates path first**. Sample 06 and pasted-from-webmail text hit
it constantly, and it must not crash the demo:

```python
usable = [c for c in candidates if not c["excluded"]]
if not usable:
    return no_origin_result(), []
```

Then `best = usable[0]` — M2 guarantees the ordering, **do not re-sort**.

### Hour 5 — the real ip-api path

```python
requests.get("http://ip-api.com/json/" + ip,
             params={"fields": IP_API_FIELDS},
             timeout=GEOIP_TIMEOUT_SECONDS)
```

Field mapping: `countryCode`→`country_code`, `regionName`→`region`, `as`→`asn`,
`hosting`→`is_datacenter`, `proxy`→`is_proxy`, `mobile`→`is_mobile`.

Wrap everything in `try/except (requests.RequestException, ValueError, KeyError)`
and fall through to `_empty_geo()`. A geo failure must degrade confidence to
`low`, never break the request. The cache (`_cache_get`/`_cache_put`, already
written) is what saves you during a 30-minute rehearsal loop against a 45
req/min free tier.

### Hour 6 — `score_risk()`

Five signals, fixed order, weights in `SIGNAL_DEFS`. **All five are always
present** in the output, `triggered` True or False — M5 renders the untriggered
ones greyed with a check, and what was checked-and-passed is as informative as
what failed.

Two specific notes:

**`REPLYTO_MISMATCH` reads M1's anomalies.** Do not recompute the domain
comparison — look for `REPLYTO_DOMAIN_MISMATCH` / `RETURNPATH_DOMAIN_MISMATCH`
in `headers["anomalies"]` and reuse the `detail` string as your evidence. One
source of truth per fact.

**`URGENCY_KEYWORDS` requires two distinct matches, not one.** "Urgent" alone
appears in plenty of legitimate business mail, and single-keyword matching makes
the entire score look unserious the moment someone tests it with a real work
email. Keep the keyword list short and defensible — a 200-word list generates
false positives you will be asked about.

---

## Definition of done

- [ ] `python -m pytest backend/tests/test_m3_intel.py -q` green
- [ ] Sample 01 → **high** confidence
- [ ] Sample 02 → **medium** confidence, band **critical**
- [ ] Sample 03 → **low** confidence
- [ ] Sample 04 → **low** confidence *despite all authentication passing*
- [ ] Sample 06 → no-origin path, `NO_ORIGIN_STATEMENT`, `map_hops == []`
- [ ] `confidence` is never `None`; `statement` is never empty
- [ ] Every entry in `map_hops` carries a `confidence` value
- [ ] Every confidence level ships with at least one written reason
- [ ] Works fully offline with `GEOIP_PROVIDER=mock`
- [ ] `IS_STUB = False` in all three files

## Traps

**ip-api is HTTP, not HTTPS, on the free tier.** HTTPS requires a paid key. Fine
for a demo; mention it as a known production hardening item rather than being
caught by it.

**Rate limit is 45 req/min** and returns HTTP 429. Your cache handles the
rehearsal loop. If you hit it during the actual demo, the fallback must be
silent and graceful — a `warnings` entry, not a crash.

**Never let `lat`/`lon` be `0, 0` when the lookup failed.** Null Island is a
pin in the Gulf of Guinea and it looks exactly like a bug. Omit the `map_hops`
entry entirely if lat or lon is missing.

**Rounding.** Round `trust_score` and coordinates so the JSON stays readable in
the demo. Nobody wants to see `1.2897000000000002` on a slide.

**Don't over-tune the weights against six samples.** They are calibration data,
not a validation set. If a judge asks how you validated the weights, the honest
answer — "rule weights reflect analyst-assigned severity, and Phase 2 replaces
them with a classifier trained on the Nazario corpus" — is much stronger than
implying you measured accuracy on six emails.

**Don't demote on `SINGLE_HOP_CHAIN`.** One `Received` hop written by a trusted
provider is the *best* evidence available — the sender connected straight to the
recipient's MX with nothing in between. Treat that code as informational.
`samples/01` has exactly one hop and must still score **high**; if hop count
feeds your ladder, that sample can never pass. Only `MALFORMED_RECEIVED_HOP`,
`BACKWARD_TIMESTAMP`, `CHAIN_GAP` and `NO_EXTERNAL_IP` are demotion inputs.
