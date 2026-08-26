# M1 — Header & Received-chain parsing

You are the foundation. Every other backend module reads your output. If your
`hop_index` ordering is wrong, five people's correct code produces wrong answers.

**Read first:** `API_CONTRACT.md` §3 (the `headers`, `received_chain` and
`chain_integrity` blocks), §5 (anomaly codes), §7 (your function signatures).

---

## Your files — you own these completely, nobody else opens them

```
backend/app/parsing/header_parser.py     parse_headers(), extract_body_text()
backend/app/parsing/received_chain.py    parse_received_chain(), assess_chain_integrity(), is_private_ip()
backend/tests/test_m1_parsing.py         your tests
```

**Never open:** anything under `intel/`, `report/`, `frontend/`,
`schemas.py`, `pipeline.py`, `main.py`, or another member's test file.

## What you produce

| Function | Fills | Consumed by |
|---|---|---|
| `parse_headers()` | `response["headers"]` | M2 (needs `from.domain`), M3 (reads `anomalies`, `body_preview`), M4 (report), M5 (UI) |
| `parse_received_chain()` | `response["received_chain"]` | M2 (ranks your hops), M5 (timeline) |
| `assess_chain_integrity()` | `response["chain_integrity"]` | M3 (`CHAIN_ANOMALY` signal + confidence demotion) |

Everything is stdlib: `email`, `email.utils`, `email.header`, `email.policy`,
`ipaddress`, `re`, `datetime`. You need zero pip installs, which means you can
start coding before anyone finishes setting up their venv.

---

## THE critical detail

Mail servers **prepend** their `Received:` header. So in raw source:

```
Received: from mx.google.com by inbox.google.com   ← TOP    = LAST hop  (recipient side)
Received: from mail.evil.tld by mx.google.com      ← BOTTOM = FIRST hop (sender side)
```

Our contract says **`hop_index == 1` is closest to the SENDER**. Therefore:

```python
raw_hops = msg.get_all("Received") or []      # newest first
ordered  = list(reversed(raw_hops))           # oldest first == sender first
hops = [parse_one_hop(h, i + 1) for i, h in enumerate(ordered)]
```

Get this backwards and the trace inverts silently — M2 will rank Google's relay
as the origin, M3 will geolocate Mountain View, and the whole demo confidently
reports the wrong country. It still *looks* plausible, which is what makes it
dangerous.

**Write `test_hop_one_is_closest_to_sender` first, before the implementation.**
It is already in your test file. Make it pass, then never worry about this again.

---

## Build order

### Hour 1 — `parse_headers()` skeleton

```python
import email
from email import policy
msg = email.message_from_string(raw_email, policy=policy.default)
```

`policy=policy.default` gives you RFC2047-decoded header values for free, which
removes most of the `=?utf-8?B?...?=` pain. Worth using from the start.

Then `parse_mailbox()` using `email.utils.parseaddr`. One trap: split the domain
on the **last** `@`, because `"a@b"@evil.tld` is legal and used deliberately to
fool naive parsers.

### Hour 2 — dates and Message-ID

```python
from email.utils import parsedate_to_datetime
from datetime import timezone
dt = parsedate_to_datetime(raw_value)                 # raises on garbage - catch it
iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
```

Keep the original string in `date_raw` — the forensic report prints the raw header
alongside the parsed value, because a forged `Date` is itself evidence.

### Hour 3–4 — the Received chain

Start with regexes for the common shape, then iterate against the six samples:

```python
RE_IP     = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
RE_FROM   = re.compile(r"\bfrom\s+([A-Za-z0-9._-]+)", re.I)
RE_BY     = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.I)
RE_PROTO  = re.compile(r"\bwith\s+(E?SMTPS?A?|LMTP|HTTP|local)\b", re.I)
```

The timestamp is the text after the **last** `;` — split on `;` and take
`[-1].strip()`. Not the first, because hostnames and ESMTP ids contain semicolons.

`Received` headers are genuinely inconsistent across providers. Do not chase a
perfect regex — set `parse_ok = False` and move on. A hop you could not fully
parse is still evidence that a hop existed, and M2 handles low-quality hops by
assigning them a low trust tier.

### Hour 5 — `assess_chain_integrity()`

Allow about 60 seconds of clock skew before counting a backward jump. Real mail
servers disagree about the time constantly, and a strict comparison flags
perfectly normal mail — which then inflates M3's risk score and makes the whole
tool look jumpy.

```python
SKEW_TOLERANCE_SECONDS = 60
```

`gaps_suspected`: compare `hop[i]["by_host"]` against `hop[i+1]["from_host"]`.
A mismatch suggests a hop was removed. Compare case-insensitively and tolerate
`hostname` vs `hostname.` and a bare IP vs a hostname — otherwise everything
looks like a gap.

### Hour 6 — anomalies

Codes are frozen in `API_CONTRACT.md` §5. Emit the code and a human-readable
`detail`; **do not assign points or severity scores beyond the enum** — M3 owns
what an anomaly is worth. This separation is what lets M3 retune weights without
touching your file.

`DISPLAY_NAME_LOOKALIKE` is the highest-value one for the demo: display name
says "PayPal Service", sending domain is `paypa1-secure.tld`. Extract
domain-looking tokens and brand words from the display name and compare against
`from.domain`.

### Last — `extract_body_text()`

Only M3's `URGENCY_KEYWORDS` signal reads this, so it is genuinely last. Walk
the MIME parts, prefer `text/plain`, strip tags from `text/html`, decode with
`errors="replace"`.

---

## Definition of done

- [ ] `python -m pytest backend/tests/test_m1_parsing.py -q` green
- [ ] All six samples parse without raising
- [ ] `06_minimal_no_headers.eml` → `parse_received_chain()` returns `[]`
- [ ] `05_broken_chain_backward_timestamps.eml` → `backward_time_jumps > 0`
- [ ] `02_spoofed_paypal_hosted.eml` → hop 1 `from_ip == "203.0.113.9"`
- [ ] Private IPs (`10.20.30.40`, `127.0.0.1`, `100.64.0.1`) → `is_private_ip` True
- [ ] `IS_STUB = False` in both files

## Traps, in the order you will hit them

**Non-UTF8 bodies.** Real phishing uses odd charsets. Always
`errors="replace"`, never bare `.decode()`.

**`is_private_ip` must fail closed.** Return `True` on `ValueError`. An
unparseable IP treated as a usable public origin would put a pin on a map for a
string that is not an address.

**CGNAT.** `100.64.0.0/10` is not `is_private` in Python's `ipaddress`. Check it
explicitly — carrier-grade NAT ranges appear in real mobile-origin mail.

**IPv6.** Some hops carry IPv6. Don't crash. Parsing them is a bonus; `parse_ok
= False` is an acceptable MVP answer, and say so if asked.

**Folded headers.** Long `Received` headers wrap across lines with leading
whitespace. `msg.get_all()` unfolds for you — but if you ever regex the raw
string directly instead, you will get half a header. Use the `email` module.

**`SINGLE_HOP_CHAIN` is a note, not a warning.** Emit it with `severity: "info"`
and nothing stronger. A one-hop chain from a trusted receiver is the cleanest
case there is, and M3's confidence ladder deliberately ignores this code — see
`API_CONTRACT.md` §5. Don't set `gaps_suspected` just because `hop_count == 1`.
