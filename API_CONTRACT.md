# API CONTRACT v1.0 — FROZEN

**Owner: M6 (Integration).** This is the single source of truth for every field
crossing a module boundary. Nobody except M6 edits this file or `backend/app/schemas.py`.

**Freeze time: end of Day 1 morning.** After that, changes require the process in §8.

Read this before you write a single line. If your module returns a shape that
disagrees with this document, your module is wrong — not the document.

---

## 1. Why this file exists

Six people writing one pipeline in two days fail for exactly one reason: two
people each build half of a boundary and the halves don't meet. So we define
every boundary up front, in writing, and we make the boundary *executable*
(Pydantic validates it at runtime — a wrong-shaped return value raises
immediately instead of silently producing a broken dashboard at 2am).

Two rules follow from this:

1. **You code against this document, not against your teammate's progress.**
   M3 does not wait for M1 to finish the parser. M3 writes against the
   `received_chain` shape below and tests with `fixtures/sample_response.json`.
2. **Nobody is ever blocked.** `GET /api/v1/mock/analyze` returns a complete,
   valid, frozen response from minute one. The frontend can be 100% finished
   before the backend parses its first real email.

---

## 2. Endpoints

| Method | Path | Purpose | Owner |
|---|---|---|---|
| GET | `/api/v1/health` | Liveness + which modules are real vs stubbed | M6 |
| POST | `/api/v1/analyze` | Main pipeline. Accepts pasted text **or** `.eml` upload | M6 |
| GET | `/api/v1/mock/analyze` | Returns `fixtures/sample_response.json` unchanged | M6 |
| GET | `/api/v1/report/{analysis_id}.json` | Forensic report, JSON | M4 |
| GET | `/api/v1/report/{analysis_id}.pdf` | Forensic report, PDF | M4 |
| GET | `/api/v1/custody-log` | Append-only SHA-256 chain-of-custody log | M4 |

Base URL in dev: `http://127.0.0.1:8000`. Interactive docs: `http://127.0.0.1:8000/docs`.

### `POST /api/v1/analyze` — request

Two accepted content types. The frontend uses whichever matches the input mode.

**A. Pasted raw source** — `Content-Type: application/json`

```json
{
  "raw_email": "Received: from mail.evil.tld ...\r\nFrom: ...\r\n\r\nbody text",
  "options": { "skip_geoip": false, "include_body_heuristics": true }
}
```

`options` is optional; both keys default as shown. `skip_geoip: true` makes the
pipeline skip network calls (use it in tests and if the venue wifi dies).

**B. File upload** — `Content-Type: multipart/form-data`

Field name is exactly `file`. Accepted extensions: `.eml`, `.txt`, `.msg`
(`.msg` may 415 — that's acceptable for MVP). Max size from
`MAX_UPLOAD_BYTES`, default 2 MB.

---

## 3. `POST /api/v1/analyze` — response 200

Full shape. **The `# owner` comments are load-bearing**: they tell you which
module is the sole producer of that block. Never populate a block you don't own.

```jsonc
{
  "schema_version": "1.0",
  "analysis_id": "b7c1f0e2-3a4b-4c5d-8e9f-0a1b2c3d4e5f",  // uuid4
  "analyzed_at": "2026-08-26T10:14:22Z",                   // UTC, ISO8601, Z suffix

  "input": {                                    // owner: M6
    "source": "paste",                          // "paste" | "file"
    "filename": null,                           // string when source=="file"
    "byte_size": 12043,
    "sha256": "9f2c...e41a"                     // hash of the exact bytes received
  },

  "headers": {                                  // owner: M1
    "from":        { "display_name": "PayPal Service", "address": "service@paypa1-secure.tld", "domain": "paypa1-secure.tld" },
    "reply_to":    { "display_name": null, "address": "collect@mailbox.ru", "domain": "mailbox.ru" },   // null if absent
    "return_path": { "display_name": null, "address": "bounce@sendgrid.net", "domain": "sendgrid.net" },// null if absent
    "to":          [ { "display_name": null, "address": "victim@gmail.com", "domain": "gmail.com" } ],
    "cc":          [],
    "subject": "Your account will be suspended within 24 hours",
    "message_id": "<a1b2c3@paypa1-secure.tld>", // null if absent
    "message_id_domain": "paypa1-secure.tld",   // null if absent/malformed
    "date": "2026-08-20T09:00:00Z",             // null if absent/unparseable
    "date_raw": "Thu, 20 Aug 2026 09:00:00 +0000",
    "x_mailer": "PHPMailer 5.2.9",              // null if absent
    "raw_header_count": 42,
    "missing_headers": ["DKIM-Signature", "Message-ID"],
    "body_preview": "Dear customer, we detected unusual...",   // first 500 chars, plaintext
    "anomalies": [                              // structural findings only, NO scoring
      { "code": "REPLYTO_DOMAIN_MISMATCH", "severity": "medium", "detail": "Reply-To mailbox.ru != From paypa1-secure.tld" }
    ]
  },

  "received_chain": [                           // owner: M1
    {
      "hop_index": 1,                           // 1 == CLOSEST TO SENDER (bottom-most Received header)
      "raw": "from mail.evil.tld ([203.0.113.9]) by mx.google.com with ESMTPS id x1",
      "from_host": "mail.evil.tld",             // null if unparseable
      "from_ip": "203.0.113.9",                 // null if none present
      "by_host": "mx.google.com",
      "by_ip": null,
      "protocol": "ESMTPS",                     // null if absent
      "tls": true,
      "timestamp": "2026-08-20T09:00:01Z",      // null if unparseable
      "timestamp_raw": "Thu, 20 Aug 2026 09:00:01 +0000",
      "is_private_ip": false,                   // RFC1918 / loopback / link-local / CGNAT
      "parse_ok": true
    }
  ],

  "chain_integrity": {                          // owner: M1
    "hop_count": 4,
    "timestamps_monotonic": true,               // do timestamps increase from hop 1 -> N
    "backward_time_jumps": 0,
    "largest_gap_seconds": 3,
    "gaps_suspected": false,                    // by_host of hop N != from_host of hop N+1
    "malformed_hops": 0,
    "notes": []
  },

  "authentication": {                           // owner: M2
    "spf":   { "result": "fail", "domain": "paypa1-secure.tld", "raw": "spf=fail (google.com: domain of ...)", "source": "Authentication-Results" },
    "dkim":  { "result": "none", "domain": null, "selector": null, "raw": null, "source": null },
    "dmarc": { "result": "fail", "policy": "reject", "raw": "dmarc=fail (p=REJECT)", "source": "Authentication-Results" },
    "arc":   { "result": "none", "raw": null },
    "alignment": {
      "spf_aligned": false,
      "dkim_aligned": false,
      "from_vs_returnpath_match": false,
      "envelope_from_domain": "sendgrid.net"
    },
    "verified_by": "mx.google.com",             // whose Authentication-Results we trusted; null if none
    "self_asserted_only": false                 // true => only the sender's own headers claim auth passed
  },

  "ip_candidates": [                            // owner: M2. SORTED: index 0 = most credible.
    {
      "ip": "203.0.113.9",
      "hop_index": 1,
      "trust_tier": "provider_observed",        // see enum in §5
      "trust_score": 0.86,                      // 0.0 .. 1.0
      "observed_by": "mx.google.com",
      "observed_by_is_trusted_receiver": true,
      "reasons": ["Recorded by Google receiving infrastructure", "Public routable address"],
      "excluded": false,
      "exclusion_reason": null                  // e.g. "RFC1918 private address"
    }
  ],

  "origin": {                                   // owner: M3
    "selected_ip": "203.0.113.9",               // null if no usable candidate
    "selected_from_hop": 1,
    "geo": {
      "country": "Singapore", "country_code": "SG",
      "region": "Central Singapore", "city": "Singapore",
      "lat": 1.2897, "lon": 103.8501,
      "isp": "DigitalOcean, LLC", "org": "DigitalOcean", "asn": "AS14061",
      "is_datacenter": true, "is_proxy": false, "is_mobile": false,
      "lookup_source": "ip-api.com"             // "ip-api.com"|"geolite2"|"cache"|"mock"|"unavailable"
    },
    "infrastructure_type": "hosting",           // see enum in §5
    "confidence": "medium",                     // "high" | "medium" | "low"  <-- NEVER null
    "confidence_reasons": [
      "IP was observed by a trusted receiving provider",
      "Address belongs to datacenter/hosting infrastructure, which obscures the operator"
    ],
    "statement": "Observed sending infrastructure is geolocated to Singapore. This represents visible email-delivery infrastructure, not a verified physical location of the sender. Confidence: medium."
  },

  "map_hops": [                                 // owner: M3. Leaflet-ready, geolocated hops only.
    { "hop_index": 1, "ip": "203.0.113.9", "lat": 1.2897, "lon": 103.8501,
      "label": "DigitalOcean — Singapore, SG", "confidence": "medium", "is_selected_origin": true }
  ],

  "risk": {                                     // owner: M3
    "score": 85,                                // int, clamped 0..100
    "band": "critical",                         // "low"(0-24) "medium"(25-49) "high"(50-74) "critical"(75-100)
    "verdict": "likely_phishing",               // see enum in §5
    "signals": [                                // ALWAYS all 5, triggered true or false. Explainability.
      { "code": "AUTH_FAIL",         "label": "SPF/DKIM/DMARC failure",           "points": 30, "triggered": true,  "evidence": "spf=fail, dmarc=fail (p=reject)" },
      { "code": "INFRA_FLAGGED",     "label": "VPN / proxy / hosting / datacenter","points": 25, "triggered": true,  "evidence": "AS14061 DigitalOcean — datacenter" },
      { "code": "REPLYTO_MISMATCH",  "label": "Reply-To domain != From domain",   "points": 20, "triggered": true,  "evidence": "mailbox.ru vs paypa1-secure.tld" },
      { "code": "CHAIN_ANOMALY",     "label": "Broken or backward Received chain","points": 15, "triggered": false, "evidence": null },
      { "code": "URGENCY_KEYWORDS",  "label": "Suspicious urgency language",      "points": 10, "triggered": true,  "evidence": "matched: 'suspended', 'within 24 hours'" }
    ]
  },

  "report": {                                   // owner: M4. null while report module is stubbed.
    "report_id": "RPT-20260826-0001",
    "generated_at": "2026-08-26T10:14:23Z",
    "json_url": "/api/v1/report/b7c1f0e2-3a4b-4c5d-8e9f-0a1b2c3d4e5f.json",
    "pdf_url":  "/api/v1/report/b7c1f0e2-3a4b-4c5d-8e9f-0a1b2c3d4e5f.pdf",
    "evidence_sha256": "4d0a...bb17",
    "custody_log_entry": 17,
    "previous_entry_hash": "1c8e...90fa"        // hash-chains entries together; null for entry 1
  },

  "warnings": ["ip-api.com rate limit reached; fell back to offline GeoLite2"],

  "timings_ms": { "parse": 12, "auth": 3, "geoip": 210, "score": 1, "report": 88, "total": 314 },

  "module_status": {                            // owner: M6. Lets the UI grey out unfinished panels.
    "parsing": "live",                          // "live" | "stub" | "error"
    "auth": "live", "ranking": "live", "geoip": "live", "scoring": "live", "report": "stub"
  }
}
```

### Hard invariants — assume these, and never violate them

- Every key above is **always present**. Absent data is `null` or `[]`, never a
  missing key. This is the difference between a frontend that renders and a
  frontend full of `undefined`.
- `origin.confidence` is never `null` and never anything but `high`/`medium`/`low`.
  If you cannot compute it, it is `"low"`.
- `origin.statement` is never empty. If `selected_ip` is `null`, use the
  no-origin wording in §6.
- `risk.signals` always has exactly 5 entries in the order shown.
- `hop_index` starts at **1 = closest to the sender**. Mail servers *prepend*
  `Received` headers, so this is the *last* `Received:` line in the raw source.
  Getting this backwards silently inverts the whole trace. It is the single most
  common bug in this entire project.
- All timestamps are UTC, ISO 8601, `Z`-suffixed. No local time, anywhere.
- A module failing degrades that block to `null`/stub and adds a `warnings`
  entry. It must never 500 the whole request.

---

## 4. Error response

Any non-200 returns this and only this:

```json
{
  "schema_version": "1.0",
  "error": { "code": "UNPARSEABLE_EMAIL", "message": "Human-readable, safe to show in the UI.", "detail": null }
}
```

| HTTP | code | when |
|---|---|---|
| 400 | `EMPTY_INPUT` | no `raw_email` and no `file` |
| 400 | `UNPARSEABLE_EMAIL` | no headers found at all |
| 413 | `FILE_TOO_LARGE` | exceeds `MAX_UPLOAD_BYTES` |
| 415 | `UNSUPPORTED_FILE_TYPE` | extension not allowed |
| 404 | `REPORT_NOT_FOUND` | unknown `analysis_id` |
| 500 | `INTERNAL` | unhandled. Message must stay generic — no stack traces to the client. |

---

## 5. Enums — copy these exactly, no improvising

```
trust_tier            : provider_observed | transit_relay | client_asserted | unverifiable
infrastructure_type   : residential_isp | corporate | hosting | vpn | tor | webmail_provider | mobile_carrier | unknown
confidence            : high | medium | low
risk.band             : low | medium | high | critical
risk.verdict          : likely_legitimate | inconclusive | suspicious | likely_phishing
spf/dkim/dmarc result : pass | fail | softfail | neutral | none | temperror | permerror
lookup_source         : ip-api.com | geolite2 | cache | mock | unavailable
module_status value   : live | stub | error
anomaly severity      : info | low | medium | high
```

Anomaly codes M1 may emit (M3 reads these, so the list is shared):
`REPLYTO_DOMAIN_MISMATCH`, `RETURNPATH_DOMAIN_MISMATCH`, `MESSAGEID_DOMAIN_MISMATCH`,
`MISSING_MESSAGE_ID`, `MISSING_DATE`, `DISPLAY_NAME_LOOKALIKE`, `MALFORMED_RECEIVED_HOP`,
`BACKWARD_TIMESTAMP`, `CHAIN_GAP`, `NO_EXTERNAL_IP`, `SINGLE_HOP_CHAIN`.

**`SINGLE_HOP_CHAIN` is informational only** and must not, on its own, demote
confidence. A single `Received` hop written by a trusted receiving provider is
the *strongest* evidence this tool can get — it means the sender connected
directly to the recipient's MX with nothing in between. Demoting on hop count
would make `samples/01` impossible to score as `high`. Only `MALFORMED_RECEIVED_HOP`,
`BACKWARD_TIMESTAMP`, `CHAIN_GAP` and `NO_EXTERNAL_IP` feed the confidence ladder.

---

## 6. Confidence rules and required wording

These are product requirements, not suggestions. Overclaiming location is the
fastest way to lose credibility with a judge who knows the domain.

**high** — IP appears in a `Received` record written by a trusted receiving
provider (Google/Microsoft/Proton/Zoho/Yahoo/Amazon SES), *and* it is not
datacenter/proxy/VPN/Tor, *and* auth context is consistent.

**medium** — a public routable IP exists and is externally observed, but
hosting/datacenter infrastructure, forwarding, or partial auth data introduces
uncertainty.

**low** — VPN / proxy / Tor / webmail-only relay / malformed or truncated chain /
conflicting metadata / no externally observed IP at all.

Origin statement template — use verbatim, substituting the bracketed parts:

> `Observed sending infrastructure is geolocated to {city, country}. This
> represents visible email-delivery infrastructure, not a verified physical
> location of the sender. Confidence: {high|medium|low}.`

When `selected_ip` is `null`, use verbatim:

> `No externally observed sending IP could be recovered from this message's
> headers. Origin infrastructure could not be geolocated. Confidence: low.`

The frontend must render the confidence label adjacent to every map pin and
every location string. A bare pin with no confidence label is a bug — report it.

---

## 7. Internal function contracts

Module boundaries *inside* the backend. These signatures are fixed at freeze
time. Implement the body however you like; do not change the signature or the
returned shape.

```python
# ---- M1  backend/app/parsing/header_parser.py --------------------------------
def parse_headers(raw_email: str) -> dict        # -> response["headers"]
def extract_body_text(raw_email: str) -> str     # plaintext, HTML stripped

# ---- M1  backend/app/parsing/received_chain.py -------------------------------
def parse_received_chain(raw_email: str) -> list[dict]   # -> response["received_chain"]
def assess_chain_integrity(chain: list[dict]) -> dict    # -> response["chain_integrity"]

# ---- M2  backend/app/parsing/auth_checks.py ----------------------------------
def evaluate_authentication(raw_email: str, headers: dict) -> dict   # -> response["authentication"]

# ---- M2  backend/app/parsing/ip_ranking.py -----------------------------------
def rank_ip_candidates(chain: list[dict], auth: dict) -> list[dict]  # -> response["ip_candidates"]
def is_trusted_receiver(hostname: str | None) -> bool

# ---- M3  backend/app/intel/geoip.py ------------------------------------------
def lookup_ip(ip: str) -> dict                   # -> origin["geo"]
def classify_infrastructure(geo: dict, hostname: str | None) -> str

# ---- M3  backend/app/intel/confidence.py -------------------------------------
def assess_confidence(candidate: dict, geo: dict, auth: dict,
                      chain_integrity: dict) -> tuple[str, list[str]]
def build_origin(candidates: list[dict], auth: dict,
                 chain_integrity: dict, skip_geoip: bool = False) -> tuple[dict, list[dict]]
                 # -> (response["origin"], response["map_hops"])

# ---- M3  backend/app/intel/risk_score.py -------------------------------------
def score_risk(headers: dict, auth: dict, origin: dict,
               chain_integrity: dict, body_text: str) -> dict   # -> response["risk"]

# ---- M4  backend/app/report/report_builder.py --------------------------------
def build_report_payload(analysis: dict) -> dict
def canonical_evidence_hash(analysis: dict) -> str   # sha256 of canonical JSON

# ---- M4  backend/app/report/pdf_renderer.py ---------------------------------
def render_pdf(payload: dict, out_path: str) -> str

# ---- M4  backend/app/report/custody_log.py ----------------------------------
def append_custody_entry(analysis_id: str, evidence_sha256: str,
                         meta: dict) -> tuple[int, str | None]   # -> (entry_no, prev_hash)
def read_custody_log() -> list[dict]
def verify_custody_chain() -> dict
```

Frontend boundaries — everything hangs off one global, `window.EFR`:

```js
// M6 owns api.js
EFR.api.analyzeText(rawEmail, options) -> Promise<analysis>
EFR.api.analyzeFile(file)             -> Promise<analysis>
EFR.api.mock()                        -> Promise<analysis>
EFR.api.health()                      -> Promise<object>
EFR.api.reportUrl(analysisId, "pdf"|"json") -> string

// M6 owns map.js
EFR.map.init(containerEl) -> void
EFR.map.plot(mapHops, origin) -> void
EFR.map.clear() -> void

// M5 owns render.js
EFR.render.results(rootEl, analysis) -> void
EFR.render.error(rootEl, errorObj) -> void
EFR.render.loading(rootEl, isLoading) -> void
```

`app.js` (M5) is the **only** file that wires DOM events to `EFR.api`,
`EFR.render` and `EFR.map`. Nothing else touches the DOM outside its own panel.

---

## 8. Changing this contract

You will want to change something. That is fine — but not silently, because a
silent change costs five other people an hour each.

1. Post in the team chat: `CONTRACT CHANGE REQUEST: <field> — <why>`.
2. M6 decides, edits `API_CONTRACT.md` **and** `schemas.py` **and**
   `fixtures/sample_response.json` in one commit.
3. M6 bumps `schema_version` (`1.0` -> `1.1`) and posts `CONTRACT v1.1 LIVE`.
4. Everyone pulls before their next commit.

**Additive changes** (new optional key, defaulted) are cheap — say so and go.
**Breaking changes** (rename, retype, remove) after Day 1 midday: the answer is
almost certainly no. Add a new field instead and leave the old one populated.
