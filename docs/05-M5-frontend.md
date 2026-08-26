# M5 — Frontend UI & dashboard

You own everything the judges actually look at. The backend can be flawless and
still lose if the dashboard doesn't make the confidence model *visible* in the
four seconds before someone starts reading.

You are also the least blocked person on the team, and you should exploit that
hard: `GET /api/v1/mock/analyze` returns a complete, frozen, contract-shaped
response **right now**, before a single line of backend logic exists. Build the
entire dashboard against it and you can be finished on Day 1.

**Read first:** `API_CONTRACT.md` §3 (every field you render), §6 (the confidence
display requirement), §7 (the `EFR` interfaces you call).

---

## Your files

```
frontend/index.html        the shell (already built - fill in as needed)
frontend/css/styles.css    design tokens + primitives (done) + your panel layouts
frontend/js/render.js      the six result panels  <- your main work
frontend/js/app.js         event wiring (already done - extend if needed)
```

**Never open:** `frontend/js/api.js` or `frontend/js/map.js` — those are M6's
libraries with fixed public interfaces. You call them, you don't edit them.
Also never open anything under `backend/`.

## What you call

```js
EFR.api.mock()                              // -> Promise<analysis>  ** start here **
EFR.api.analyzeText(raw, {skip_geoip:bool}) // -> Promise<analysis>
EFR.api.analyzeFile(file)                   // -> Promise<analysis>
EFR.api.reportUrl(analysisId, "pdf"|"json") // -> string
EFR.map.init(containerEl); EFR.map.plot(analysis.map_hops, analysis.origin);
```

Errors reject with `.code` and `.userMessage` already set, so
`EFR.render.error()` has something human to display.

---

## Start here — literally the first thing you do

```bash
bash scripts/run_backend.sh     # terminal 1
bash scripts/run_frontend.sh    # terminal 2
# open http://127.0.0.1:5500 and click "Load demo response"
```

That renders the frozen fixture through your (currently stubbed) panels. Every
field you will ever need is in that response. Now fill in the six panel builders
in `render.js` one at a time — each one is independently demoable, so you always
have something to show at a checkpoint.

**Serve over HTTP, never open `index.html` via `file://`.** A `file://` origin
gets CORS-blocked on every `fetch()` and the failure message won't tell you that.
It is a guaranteed twenty minutes if you skip this.

---

## Build order — highest visual payoff first

### 1 · Verdict panel (do this first)

The big number. `analysis.risk.score` at ~56px, coloured by
`analysis.risk.band`, with the humanised `verdict` beside it. Then the subject
line, the From address, and — importantly — `analysis.origin.statement` **in
full**.

That statement is the headline finding of the whole tool. Do not truncate it, do
not put it behind a "read more".

Colour classes already exist: `.pill-low`, `.pill-medium`, `.pill-risk-high`,
`.pill-risk-critical`.

> **Watch the colour collision.** "High" means high *confidence* (good) and high
> *risk* (bad). Use `.pill-high` for confidence and `.pill-risk-high` for the
> risk band — they are deliberately different colours in the CSS. Getting these
> crossed makes a dangerous email look safe.

### 2 · Authentication panel (quick win)

SPF / DKIM / DMARC as three pass/fail badges. Then `verified_by`:

> "Verified by mx.google.com"

And if `analysis.authentication.self_asserted_only` is `true`, show it loudly:

> ⚠ **Self-asserted only** — this message claims authentication passed, but no
> trusted receiving provider recorded a result.

That banner is one of the strongest things the tool surfaces. Give it real
visual weight, not a footnote.

### 3 · Origin panel (the differentiator)

Create `<div id="map" class="map"></div>` — `app.js` calls `EFR.map.init()` and
`EFR.map.plot()` after your render completes.

**Hard requirement from `API_CONTRACT.md` §6:** the confidence label sits
*directly beside* the location string, and **every** `confidence_reason` is
listed. A location shown without its confidence label is a contract violation —
if you see one, report it rather than shipping it.

```
Singapore, SG   [confidence: medium]
DigitalOcean, LLC · AS14061 · hosting

Why this confidence level:
 · The address was observed and recorded by a trusted receiving provider.
 · The address belongs to datacenter/hosting infrastructure, which identifies a
   rented server rather than the operator's own connection.
 · SPF and DKIM did not pass, so the sending domain cannot corroborate this route.
```

Handle `selected_ip === null` — sample 06 hits it. Show the no-origin statement
and hide the map, don't render an empty grey box.

### 4 · Routing chain panel

`analysis.received_chain` as a vertical timeline, **hop 1 at the top**, labelled
"closest to sender". Per hop: timestamp, `from_host`, `from_ip`, `by_host`, TLS
indicator.

Cross-reference `analysis.ip_candidates` by IP: grey out hops whose candidate has
`excluded: true` and show the `exclusion_reason` inline ("RFC1918 private
address, not externally routable"). Showing what was rejected and why is more
persuasive than showing only the answer.

### 5 · Risk signals panel

All five `analysis.risk.signals` as rows: label, points, evidence. Render
untriggered ones greyed with a check mark. What was checked and passed is as
informative as what failed, and it makes the score look like an assessment rather
than an accusation.

### 6 · Evidence & custody panel

`analysis.report.evidence_sha256` in monospace (`.mono` class exists), the
custody entry number, and download buttons via `EFR.api.reportUrl()`.

`analysis.report` is `null` while M4's module is stubbed — show a disabled state,
not an error.

---

## Escape everything user-controlled

`EFR.render.esc()` is already written. Use it on every interpolated value —
subject lines, display names, hostnames, evidence strings.

Phishing subject lines contain HTML, and some contain deliberate markup. An
unescaped subject either breaks your layout mid-demo or injects into your page.
Both are avoidable with one function call.

---

## Definition of done

- [ ] All six panels render from `EFR.api.mock()` with no console errors
- [ ] Real analysis renders correctly for all six samples
- [ ] Every location string has a confidence label adjacent to it
- [ ] `origin.statement` shown in full, unmodified
- [ ] Every `confidence_reason` listed
- [ ] Untriggered risk signals visible but greyed
- [ ] Excluded hops greyed with their exclusion reason
- [ ] Sample 06 (no origin) renders without an empty map or a crash
- [ ] `report: null` renders a disabled download state
- [ ] Backend-offline renders a readable error, not a blank page
- [ ] Legible on a projector: check at 1280×720, and stand three metres back
- [ ] `module_status` chips visible in the header

## Traps

**The map renders as a grey sliver.** Leaflet mis-sizes itself when its container
is `display:none` at init. `EFR.map.plot()` already calls `invalidateSize()`, but
if you add tabs or collapsible panels, call it again after the panel becomes
visible.

**Null Island.** If a hop's `lat`/`lon` are missing, `EFR.map.plot()` skips it —
don't "fix" that by defaulting to `0, 0`. A pin in the Gulf of Guinea looks
exactly like a bug because it is one.

**Long values overflow.** Base64 DKIM signatures and 64-char hashes need
`overflow-wrap: anywhere` or they blow out the layout. Test with the fixture,
which has real-length values.

**Don't add a framework.** No React, no build step, no npm. Six laptops, two
days — a build step that works on five of them is a build step that doesn't work.

**Projector reality.** Contrast that looks fine on your laptop can be unreadable
on venue hardware. The palette in `styles.css` is already high-contrast; if you
change it, check it from three metres away.
