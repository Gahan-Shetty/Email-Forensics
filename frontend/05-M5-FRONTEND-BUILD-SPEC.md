# M5 — Frontend build spec (appearance, workflow, technical detail)

Companion to `docs/05-M5-frontend.md`. That file tells you *what* to build and in
what order. This one tells you *how it should look and behave* — screen anatomy,
the interaction states, the DOM you emit, the CSS you still need to write, and
the exact copy. Read the other one first; it is shorter.

Everything here is derived from `fixtures/sample_response.json` and
`API_CONTRACT.md`. Where the two disagree, the contract wins and you should tell
M6.

---

## 0 · Ground rules (read once, they save hours)

**Your four files, and nothing else.**

```
frontend/index.html        the shell — already built, extend as needed
frontend/css/styles.css    tokens + primitives done; panel layouts are yours
frontend/js/render.js      the six panel builders  ← 80% of your work is here
frontend/js/app.js         event wiring — already done, extend if needed
```

`frontend/js/api.js` and `frontend/js/map.js` are M6's. They are libraries with
fixed public interfaces, not screens. You call them; you never open them. If one
misbehaves, post `CONTRACT CHANGE REQUEST` — don't patch it locally, because your
patch will collide with M6's next commit.

**No framework, no build step, no npm.** Six laptops, two days. A build step that
works on five of them is a build step that doesn't work. Plain ES5-flavoured JS
in an IIFE, exactly like the existing files.

**Always serve over HTTP.** `bash scripts/run_frontend.sh`, then
`http://127.0.0.1:5500`. Opening `index.html` as `file://` CORS-blocks every
`fetch()` and the error message will not tell you that. Guaranteed twenty
minutes if you forget.

**Script order in `index.html` is load-bearing:** leaflet → api.js → map.js →
render.js → app.js. `app.js` must be last because it reads `EFR.render` at
definition time.

**You render; you never fetch.** All data arrives as the `analysis` argument,
already contract-shaped and already validated by Pydantic on the way out. Every
key is guaranteed present — absent data is `null` or `[]`, never a missing key.
So `a.origin.confidence` is always safe to read; `a.origin.geo.city` may be
`null` and you handle that in the view.

---

## 1 · The workflow, as a state machine

There are only five states. Build each one deliberately — the two people who lose
demos are the one who forgot the error state and the one whose loading state
flashes so fast nobody believes work happened.

```
                    ┌──────────────────────────────────────┐
      page load ───►│  A · IDLE                            │
                    │  input panel only, no results div    │
                    │  header chips populated from /health │
                    └───────────────┬──────────────────────┘
                                    │ click Analyze / Load demo
                                    ▼
                    ┌──────────────────────────────────────┐
                    │  B · LOADING                          │
                    │  spinner + "Analyzing message…"       │
                    │  results div REPLACED, not appended   │
                    └──────┬────────────────────┬───────────┘
                  resolve  │                    │  reject
                           ▼                    ▼
        ┌──────────────────────────┐   ┌────────────────────────────┐
        │  C · RESULTS             │   │  D · ERROR                 │
        │  warnings banner (if any)│   │  banner-error with          │
        │  6 panels in order       │   │  err.code + err.userMessage │
        │  map init AFTER render   │   │  input panel stays intact   │
        └──────────┬───────────────┘   └────────────────────────────┘
                   │ any block null / module stubbed
                   ▼
        ┌──────────────────────────┐
        │  E · PARTIAL             │
        │  panel renders a disabled│
        │  state, never an error   │
        └──────────────────────────┘
```

State E is the one people skip and it is the one you will actually be looking at
for most of Day 1, because M1/M2/M3 are still stubs. Design it first-class:
**a stubbed block is a known, labelled gap, not a failure.** The header chips
already tell the viewer which modules are live, so a greyed panel reads as honest
rather than broken.

`app.js` already implements A→B→C/D. What you add is the *content* of C and the
per-panel behaviour of E.

### The map ordering trap, spelled out

Leaflet measures its container at `init()`. The container does not exist until
`panelOrigin()` has run and been appended. So the order is fixed and `app.js`
already gets it right:

```
EFR.render.results(...)   // creates <div id="map">
  → document.getElementById("map")
  → EFR.map.init(el)
  → EFR.map.plot(a.map_hops, a.origin)
```

If you later add tabs or collapsible panels, a map that was hidden at init will
render as a grey sliver. `EFR.map.plot()` calls `invalidateSize()` for you, so
the fix is to call `plot()` again after the panel becomes visible — not to hack
around the sizing.

---

## 2 · Screen anatomy

One column, max 1060px, centred. Do **not** go two-column: on a projector at
1280×720 a two-column layout halves your effective type size, and the report
reads top-to-bottom like a document, which is the impression you want.

```
┌───────────────────────────────────────────────────────────────────────────┐
│ ▉ EFA   Email Forensic Analyzer                 [PARSING·live] [AUTH·live] │  ← .topbar
│         Header forensics · confidence-scored…   [GEOIP·stub] [REPORT·live] │    (built)
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─ 1 · SUBMIT A MESSAGE ───────────────────────────────────────────────┐ │  ← #panel-input
│  │  [Paste raw source] [Upload .eml]                                    │ │    (built)
│  │  ┌────────────────────────────────────────────────────────────────┐  │ │
│  │  │ Paste the FULL raw source, including Received: and From:…      │  │ │
│  │  └────────────────────────────────────────────────────────────────┘  │ │
│  │  [ Analyze message ]  [ Load demo response ]   ☐ Offline mode        │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ⚠ Notes  ip-api.com rate limit reached; fell back to GeoLite2            │  ← warnings
│                                                                           │    (built)
│  ┌─ VERDICT ────────────────────────────────────────────────────────────┐ │
│  │                                                                      │ │
│  │    85      LIKELY PHISHING   [critical]                              │ │
│  │   /100                                                               │ │
│  │                                                                      │ │
│  │   Your account will be suspended within 24 hours                     │ │
│  │   PayPal Service <service@paypa1-secure.tld>                         │ │
│  │                                                                      │ │
│  │   ┌────────────────────────────────────────────────────────────────┐ │ │
│  │   │ Observed sending infrastructure is geolocated to Singapore,    │ │ │
│  │   │ SG. This represents visible email-delivery infrastructure,     │ │ │
│  │   │ not a verified physical location of the sender.                │ │ │
│  │   │ Confidence: medium.                                            │ │ │
│  │   └────────────────────────────────────────────────────────────────┘ │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─ AUTHENTICATION ─────────────────────────────────────────────────────┐ │
│  │  SPF ✕ fail    DKIM — none    DMARC ✕ fail (p=reject)   ARC — none   │ │
│  │  Results as recorded by mx.google.com                                │ │
│  │  SPF aligned ✕ · DKIM aligned ✕ · From matches Return-Path ✕         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─ ORIGIN ─────────────────────────────────────────────────────────────┐ │
│  │  ┌──────────────────────────── map ───────────────────────────────┐  │ │
│  │  │            ● Singapore (origin)      ○ Mountain View           │  │ │
│  │  └────────────────────────────────────────────────────────────────┘  │ │
│  │  203.0.113.9  ·  hop 1                                               │ │
│  │  Singapore, Central Singapore, Singapore   [confidence: medium]      │ │
│  │  DigitalOcean, LLC · AS14061 · hosting · datacenter                  │ │
│  │                                                                      │ │
│  │  Why this confidence level:                                          │ │
│  │   · IP was observed by a trusted receiving provider                  │ │
│  │   · Address belongs to datacenter/hosting infrastructure, which…     │ │
│  │   · SPF and DKIM did not pass, so the sending domain cannot…         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─ ROUTING CHAIN ──────────────────────────────────────────────────────┐ │
│  │  ● hop 1 · closest to sender    09:00:01Z                            │ │
│  │  │  mail.evil.tld  203.0.113.9  →  mx.google.com        🔒 TLS       │ │
│  │  ●  hop 2                        09:00:03Z                           │ │
│  │  │  mail-sor-f41.google.com  209.85.220.41  →  inbox     🔒 TLS      │ │
│  │  ○  hop 3   (greyed)             09:00:04Z                           │ │
│  │     10.20.30.40 — RFC1918 private address, not externally routable   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─ RISK SIGNALS ───────────────────────────────────────────────────────┐ │
│  │  ✕ SPF/DKIM/DMARC failure              +30   spf=fail, dmarc=fail    │ │
│  │  ✕ VPN / proxy / hosting / datacenter   +25   AS14061 DigitalOcean   │ │
│  │  ✕ Reply-To domain != From domain       +20   mailbox.ru vs paypa1…  │ │
│  │  ✓ Broken or backward Received chain     0    not triggered  (grey)  │ │
│  │  ✕ Suspicious urgency language          +10   'suspended', 'within…' │ │
│  │                                        ────                          │ │
│  │                                          85 / 100                    │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─ EVIDENCE & CUSTODY ─────────────────────────────────────────────────┐ │
│  │  Evidence SHA-256                                                    │ │
│  │  4adf0baedaf7f360bc9377e39df38326a385d3f78082b3858517a15d842a9f7d    │ │
│  │  Custody entry 17 · chain intact ✓                                   │ │
│  │  [ Download JSON ]  [ Download PDF ]                                 │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────────────────┤
│  Origin locations describe visible email-delivery infrastructure, not a    │  ← .footer
│  verified physical location of any sender…                                 │    (built)
└───────────────────────────────────────────────────────────────────────────┘
```

Panel order is fixed by `EFR.render.results()` and it is the right order: the
answer first, then the evidence for it, then the mechanics. Don't reorder to put
the map first — the map is the prettiest panel and the statement is the honest
one, and the statement has to land before the picture does.

---

## 3 · Panel specs

Each panel is a `<section class="panel">` with an uppercase `<h2>`. That styling
already exists. Below, "fields" are exactly what you read from `analysis`.

### 3.1 Verdict

**Fields:** `risk.score`, `risk.band`, `risk.verdict`, `headers.subject`,
`headers.from.display_name`, `headers.from.address`, `origin.statement`.

The score is the only genuinely large type on the page: ~56px, weight 700,
tabular figures, coloured by band. Put `/100` under it in small muted type so the
scale is unambiguous — an unqualified "85" reads as a percentage to some people.

The verdict goes beside it, humanised: `verdict.replace(/_/g, " ")` →
"likely phishing". Sentence case, not shouty caps, and a band pill next to it.

Then subject and From on their own lines. `esc()` both — this is the single most
likely place for a phishing sample to inject markup.

Then `origin.statement` **in full, verbatim, never truncated, never behind a
"read more"**. Give it a bordered or tinted box so it reads as a quoted finding
rather than body copy. This sentence is the whole product thesis: it is what
separates this tool from a header parser that claims to have found someone's
house. `API_CONTRACT.md` §6 fixes its wording; you render the string you are
given and you do not reformat it.

Edge case: if `risk` is `{}` because M3 is stubbed, show `—/100`, the word
"pending", and a `chip-stub`. Don't render `undefined`.

### 3.2 Authentication

**Fields:** `authentication.spf|dkim|dmarc|arc` (each `.result`, `.domain`,
`.raw`, plus `.policy` on dmarc and `.selector` on dkim), `authentication.
verified_by`, `authentication.alignment.*`, `authentication.self_asserted_only`.

Four badges in a row. Map result → colour with a lookup, not a ternary, because
there are seven possible results:

| result | glyph | colour token |
|---|---|---|
| `pass` | ✓ | `--low` (green) |
| `fail`, `permerror` | ✕ | `--critical` |
| `softfail` | ~ | `--high` |
| `neutral`, `none` | — | `--ink-muted` |
| `temperror` | ? | `--medium` |

Under the badges: `Results as recorded by {verified_by}`, or when `verified_by`
is null, `No trusted receiver recorded a result`. Put the raw header text in a
`.mono` line or a `<details>` — judges who know the domain will look for it, and
having it there is worth more than the space it costs.

**If `self_asserted_only` is true, this becomes the loudest thing on the page
after the score.** Full-width `banner-warn` above the badges:

> ⚠ **Self-asserted only** — this message claims authentication passed, but no
> trusted receiving provider recorded a result. These results carry no
> evidentiary weight.

That banner is one of the strongest findings the tool produces. A footnote-sized
version of it is a wasted feature.

### 3.3 Origin — the differentiator

**Fields:** `origin.selected_ip`, `origin.selected_from_hop`, `origin.geo.*`,
`origin.infrastructure_type`, `origin.confidence`, `origin.confidence_reasons[]`,
plus `map_hops` (which you pass through to `EFR.map`, you don't render it).

Create `<div id="map" class="map"></div>` inside this panel. `.map` is already
styled at 340px tall. `app.js` does the rest.

**Two hard requirements from `API_CONTRACT.md` §6:**

1. The confidence label sits *directly adjacent* to the location string. Same
   line, ideally as a pill immediately after it. Not in a corner, not in a
   tooltip, not further down the panel. A location rendered without its
   confidence label is a contract violation — if you find one anywhere in the UI,
   report it instead of shipping it.
2. **Every** `confidence_reason` is listed. Not the first two, not a summary. The
   reasons are the argument for why the label is credible; truncating them is
   removing the evidence and keeping the claim.

Layout, in order: IP + hop, then location + confidence pill, then
`isp · asn · infrastructure_type` with datacenter/proxy/mobile flags, then the
"Why this confidence level" list.

**`selected_ip === null` is a first-class case, not an error** — sample 06 hits
it, and so does any webmail-only message. Hide the map entirely (don't render an
empty grey box, and don't default coordinates to `0,0` — a pin in the Gulf of
Guinea looks exactly like the bug it is). Show the no-origin statement from the
contract and the confidence pill reading `low`.

### 3.4 Routing chain

**Fields:** `received_chain[]` (`hop_index`, `timestamp`, `timestamp_raw`,
`from_host`, `from_ip`, `by_host`, `protocol`, `tls`, `is_private_ip`,
`parse_ok`), `chain_integrity.*`, cross-referenced against `ip_candidates[]`.

A vertical timeline, **hop 1 at the top**, and label it "closest to sender"
explicitly. Mail servers prepend `Received:` headers, so hop 1 is the *last* line
in the raw source; M1 already reversed it for you and you present the order you
are given. Inverting this silently inverts the entire trace and it is the most
common bug in the project — put the label in the UI so a reviewer can catch it.

Per hop: `hop_index`, timestamp, `from_host`, `from_ip`, an arrow, `by_host`, and
a TLS indicator. Build the candidate cross-reference once, outside the loop:

```js
var byIp = {};
(a.ip_candidates || []).forEach(function (c) { byIp[c.ip] = c; });
```

Then for each hop, if `byIp[hop.from_ip]` exists and is `excluded`, grey the row
and print `exclusion_reason` inline — "RFC1918 private address, not externally
routable". Showing what you rejected and why is more persuasive than showing only
the winner; it is the visible proof that the tool ranked candidates rather than
grabbing the first IP it saw.

Below the timeline, a compact integrity strip from `chain_integrity`: hop count,
timestamps in order, backward jumps, largest gap, malformed hops. Render
`notes[]` as bullets if present.

Empty `received_chain` → "No Received headers were recoverable from this
message." Not an empty panel.

### 3.5 Risk signals

**Fields:** `risk.signals[]` — always exactly five, in a fixed order, triggered
or not.

Render **all five, always.** Triggered rows get the ✕ glyph, the points, and the
`evidence` string. Untriggered rows stay visible, greyed, ✓, points shown as `0`
or `—`, evidence "not triggered". Then a total row.

This is deliberate and worth understanding: showing the two checks that *passed*
is what makes the number read as an assessment rather than an accusation. A panel
that lists only failures looks like it went looking for them.

`evidence` is model-generated text containing quoted fragments of the email —
`esc()` it.

### 3.6 Evidence & custody

**Fields:** `report.evidence_sha256`, `report.custody_log_entry`,
`report.previous_entry_hash`, `report.report_id`, `analysis_id`. Optionally
`EFR.api.custodyLog()` for the chain-intact line.

The 64-char digest in `.mono` with `overflow-wrap: anywhere`, labelled "Evidence
SHA-256". Then `Custody entry {n}`. Then two buttons built with
`EFR.api.reportUrl(a.analysis_id, "json")` and `"pdf"` — plain `<a>` with
`download`, or `target="_blank"`.

Nice-to-have that pays for itself in the demo: call `EFR.api.custodyLog()` and
render `verification.intact` as `chain intact ✓` / `chain broken at entry N ✕`.
It costs four lines and it sets up the tamper demo — someone edits a character in
`evidence/custody_log.jsonl`, you reload, and the badge flips. Do it only after
the other five panels are done.

**`report` is `null` whenever the report module is stubbed or errored.** Render a
disabled state — greyed buttons, "Report generation pending" — not an error
banner. Same for `custody_log_entry` being null: "not yet written to the custody
log".

---

## 4 · Design system

The tokens in `styles.css` are done. Use them; don't introduce new hex values.

```
--bg #f6f7f9   --surface #fff   --ink #14171a   --ink-muted #5b6470
--line #dfe3e8   --accent #1f3a8a
--low #1a7f37   --medium #9a6700   --high #bc4c00   --critical #b3261e
--radius 10px   --shadow (defined)   --mono / --sans
```

**Type scale.** Only three sizes carry meaning: the score (~56px/700), section
headings (12px/700 uppercase, already styled), body (15px). Everything else is
13.5px muted. Resist adding a fourth — inconsistent type size is what makes a
two-day dashboard look like a two-day dashboard.

**Spacing rhythm.** Panels are already 20/22px padded with 18px gaps. Inside a
panel use 4 / 8 / 14 / 20 and nothing between.

### The colour collision — resolve this before you style anything

"High" is good for confidence and bad for risk. The CSS ships with

```css
.pill-high, .pill-low { color: var(--low); }   /* both green */
```

which is correct for *risk band low* and for *confidence high*, and actively
wrong for *confidence low* — it would paint an unreliable result reassuring
green. Don't paper over it with a ternary at the call site. Add a second,
explicitly-named family in your own file:

```css
/* confidence: how much we trust the finding.   high = good */
.pill-conf-high   { color: #1a7f37; }
.pill-conf-medium { color: #9a6700; }
.pill-conf-low    { color: #b3261e; }
```

Those three hex values are deliberately identical to `CONFIDENCE_COLOURS` in
`backend/app/report/pdf_renderer.py`, and `--low/--medium/--high/--critical`
match `BAND_COLOURS` in the same file. **The PDF and the screen must agree**, so
if you change a palette value, tell M4 in the same breath.

Then be rigid about which family you use:

| meaning | classes | source field |
|---|---|---|
| risk band | `.pill-low` `.pill-medium` `.pill-risk-high` `.pill-risk-critical` | `risk.band` |
| confidence | `.pill-conf-high` `.pill-conf-medium` `.pill-conf-low` | `origin.confidence`, `map_hops[].confidence` |
| module state | `.chip-live` `.chip-stub` `.chip-error` | `module_status.*` |

Note `EFR.map.js` currently emits `pill-{confidence}` in its popups. That is
M6's file — if the popup colour looks wrong once you add the `conf` family, raise
it with M6 rather than editing `map.js`.

### CSS classes you still need to write

Everything above is primitives. These are yours to invent, and this naming keeps
them out of anyone's way:

```
.verdict-score .verdict-meta .statement-box
.auth-badges .auth-badge .auth-badge--pass/fail/neutral
.hop-list .hop .hop--excluded .hop-time .hop-hosts .hop-tls
.signal-row .signal-row--off .signal-points .signal-total
.kv .kv-key .kv-value          (reusable label/value grid — write it once)
.reasons                        (the confidence bullet list)
.digest                         (mono + overflow-wrap: anywhere)
```

Write `.kv` first. Four of the six panels are label/value grids, and doing it
once as a two-column CSS grid saves you writing four near-identical blocks.

---

## 5 · render.js architecture

Keep the existing shape: one builder per panel, each returning a DOM node via
`el()`, assembled by `results()`. Don't refactor to a template engine.

```js
function panelVerdict(a) {
  var risk = a.risk || {};
  var from = (a.headers && a.headers.from) || {};
  return el(
    '<section class="panel">' +
      '<h2>Verdict</h2>' +
      '<div class="verdict-score" style="color:' + bandColour(risk.band) + '">' +
        esc(risk.score == null ? "—" : risk.score) +
        '<span class="muted">/100</span>' +
      '</div>' +
      '<p class="verdict-meta">' + esc(humanise(risk.verdict)) + ' ' +
        pill(risk.band || "unknown", bandClass(risk.band)) + '</p>' +
      '<p>' + esc(a.headers && a.headers.subject) + '</p>' +
      '<p class="muted">' + esc(mailbox(from)) + '</p>' +
      '<div class="statement-box">' + esc(a.origin && a.origin.statement) + '</div>' +
    '</section>');
}
```

Small helpers worth writing once at the top, next to `esc`:

```js
function humanise(s)   { return String(s || "inconclusive").replace(/_/g, " "); }
function mailbox(mb)   { return mb.display_name ? mb.display_name + " <" + mb.address + ">"
                                                : (mb.address || "—"); }
function dash(v)       { return (v === null || v === undefined || v === "") ? "—" : v; }
function bandClass(b)  { return ({low:"low",medium:"medium",high:"risk-high",
                                  critical:"risk-critical"})[b] || "medium"; }
function confClass(c)  { return "conf-" + (({high:"high",medium:"medium",low:"low"})[c] || "low"); }
function kv(rows)      { /* [[label, value], …] -> .kv grid html */ }
```

`dash()` is the one that saves you: it stops `null` and `undefined` reaching the
page as text, which is the single most common visual bug in a dashboard built
against partially-stubbed data.

**`esc()` discipline.** Every interpolated value that came from the email goes
through `esc()`: subjects, display names, hostnames, raw auth headers, evidence
strings, exclusion reasons, warnings. Phishing subject lines contain HTML — some
deliberately. An unescaped one either breaks your layout mid-demo or injects into
your page. The rule that is easy to follow: if it came from `analysis`, it gets
`esc()`; if you typed it, it doesn't.

---

## 6 · Degraded-state matrix

Pin this up. It is what you'll be building against all of Day 1, and it's also
the difference between a demo that survives a broken module and one that doesn't.

| Condition | What the panel shows |
|---|---|
| `risk` empty (M3 stubbed) | `—/100`, "assessment pending", stub chip |
| `authentication` empty (M2 stubbed) | four `—` badges, "authentication not yet evaluated" |
| `authentication.self_asserted_only` | full-width warn banner, badges below |
| `received_chain` `[]` | "No Received headers were recoverable from this message." |
| `origin.selected_ip` null | no map, no-origin statement, confidence pill `low` |
| `origin.confidence_reasons` `[]` | "No basis recorded." (never an empty list) |
| `map_hops` `[]` | hide the map container entirely |
| a hop's `lat`/`lon` null | `EFR.map.plot` skips it — do not default to `0,0` |
| `report` null (M4 stubbed) | greyed buttons, "report generation pending" |
| `warnings` non-empty | `banner-warn` above all panels (already wired) |
| `/health` unreachable | header shows `chip-error backend offline` (already wired) |
| any `module_status` = `error` | that panel's heading gets a `chip-error` |

The general principle, and it's worth stating to a judge if asked: **a module
that isn't finished degrades one panel and says so.** Nothing in the UI ever
claims data it doesn't have.

---

## 7 · Projector and demo reality

You are presenting on venue hardware you have not seen, probably at 1280×720,
possibly washed out, from three metres away.

- Test at 1280×720 with the browser at 100%, then stand up and walk back three
  metres. If you can't read the score and the statement, nothing else matters.
- The shipped palette is already high-contrast. If you change a colour, re-check
  it — contrast that looks fine on a laptop can vanish on a projector.
- Long values overflow: 64-char hashes, base64 DKIM signatures, 100-char
  `Received` lines. `overflow-wrap: anywhere` on `.mono` and `.digest`. Test with
  the fixture, which has real-length values in it.
- Keep the whole result reachable in about two scrolls. A judge will not scroll
  five times.
- Don't animate anything except the existing spinner.
- Have `Load demo response` working at all times. If the backend dies thirty
  seconds before you present, that button is the demo.

---

## 8 · Accessibility (cheap, and it reads as polish)

Most of it is already in the shell: `aria-live="polite"` on `#results` and
`#module-status`, `role="tablist"`, `.sr-only` label on the textarea, a
focusable dropzone with Enter/Space handling.

What you add: never encode meaning in colour alone — every pass/fail badge gets
a glyph *and* a word, so ✓/✕ plus "pass"/"fail". Keep one `<h2>` per panel and
don't skip heading levels. Ensure the focus outline on buttons survives your
CSS; `:focus` styling already exists for the textarea and dropzone.

---

## 9 · Build order and checkpoints

| Slot | Do | You can demo |
|---|---|---|
| Hour 0–1 | Both servers up, click "Load demo response", see six TODO panels | the plumbing works |
| Hour 1–3 | `.kv` helper + Verdict panel complete | the big number and the statement |
| Hour 3–4 | Auth panel + the self-asserted banner | the strongest finding |
| Day 1 PM | Origin panel + map + confidence adjacency + reasons | the differentiator |
| Day 1 PM | Routing timeline with excluded hops greyed | the working, not just the answer |
| Day 1 eve | Risk signals, all five | explainability |
| Day 2 AM | Evidence panel + download buttons; then custody-intact line | tamper-evidence |
| Day 2 AM | All six samples through the real backend | it's not just the fixture |
| Day 2 PM | Projector check, overflow check, degraded states | it survives |

Each row is independently demoable. That's the point — at any checkpoint you have
something finished rather than six things half-built.

---

## 10 · Copy deck

Use these strings as written. They're aligned with `API_CONTRACT.md` §6 and with
the wording M4 puts in the PDF, so the screen and the exported report say the
same thing. Inconsistent hedging between the two is the kind of thing a sharp
judge notices.

| Situation | Copy |
|---|---|
| no trusted receiver | `No trusted receiver recorded a result` |
| self-asserted auth | `Self-asserted only — this message claims authentication passed, but no trusted receiving provider recorded a result. These results carry no evidentiary weight.` |
| no origin IP | use `origin.statement` verbatim (contract §6 supplies it) |
| confidence list heading | `Why this confidence level:` |
| no reasons | `No basis recorded.` |
| no hops | `No Received headers were recoverable from this message.` |
| excluded hop | print `exclusion_reason` verbatim from `ip_candidates` |
| untriggered signal | `not triggered` |
| report stubbed | `Report generation pending` |
| hop 1 label | `closest to sender` |
| custody intact | `chain intact` / `chain broken at entry {n}` |

Never write "located in", "the sender is in", or "traced to". The tool reports
*observed sending infrastructure*, and every sentence in the UI should be
survivable under the question "how do you know that?"

---

## 11 · Definition of done

`docs/05-M5-frontend.md` has the functional checklist. These are the
appearance-and-behaviour additions:

- [ ] All five states (idle, loading, results, error, partial) reachable and deliberate
- [ ] Every location string has its confidence label adjacent — no exceptions
- [ ] `origin.statement` rendered in full, unmodified, visually set apart
- [ ] Every `confidence_reason` listed, never truncated
- [ ] All five risk signals shown; untriggered ones greyed, not hidden
- [ ] Excluded hops greyed with the reason inline
- [ ] Confidence pills use the `.pill-conf-*` family, risk pills use the band family
- [ ] Sample 06 renders with no map and no console error
- [ ] `report: null` renders disabled downloads, not an error
- [ ] Backend stopped → readable error banner, input panel still usable
- [ ] No `undefined`, `null` or `NaN` visible anywhere in any of the six samples
- [ ] 64-char hash and a long DKIM value don't break the layout
- [ ] Legible at 1280×720 from three metres
- [ ] Zero console errors across all six samples
- [ ] `module_status` chips visible and correct in the header
