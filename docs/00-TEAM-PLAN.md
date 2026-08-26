# Team plan & conflict-avoidance rules

Read this once, in full, before you open your own member file. It is short.

---

## 1. Who owns what

Six members, six non-overlapping file territories. **The ownership rule is
absolute: one file, one owner.** If two people never open the same file, git
never produces a conflict — that is the entire mechanism, and it is why the
split below looks slightly unusual in places.

| # | Member | Track | Exclusive files |
|---|---|---|---|
| **M1** | | Header & Received-chain parsing | `backend/app/parsing/header_parser.py`, `backend/app/parsing/received_chain.py`, `backend/tests/test_m1_parsing.py` |
| **M2** | | Authentication & IP trust ranking | `backend/app/parsing/auth_checks.py`, `backend/app/parsing/ip_ranking.py`, `backend/tests/test_m2_auth_ranking.py` |
| **M3** | | Geolocation, confidence model, risk scoring | `backend/app/intel/geoip.py`, `backend/app/intel/confidence.py`, `backend/app/intel/risk_score.py`, `backend/tests/test_m3_intel.py` |
| **M4** | | Forensic report & chain of custody | `backend/app/report/report_builder.py`, `backend/app/report/pdf_renderer.py`, `backend/app/report/custody_log.py`, `backend/tests/test_m4_report.py` |
| **M5** | | Frontend UI & dashboard | `frontend/index.html`, `frontend/css/styles.css`, `frontend/js/render.js`, `frontend/js/app.js` |
| **M6** | | Integration, contract, map, samples, pitch | `API_CONTRACT.md`, `backend/app/schemas.py`, `backend/app/main.py`, `backend/app/pipeline.py`, `backend/app/core/config.py`, `frontend/js/api.js`, `frontend/js/map.js`, `fixtures/`, `samples/`, `backend/tests/test_contract.py`, `backend/tests/test_m6_api.py`, `pitch/` |

Write your name into the table above and commit that as the first change.

### Why M6 owns the contract *and* the orchestrator

`schemas.py` and `pipeline.py` are the two files that every other file depends
on. They are also the two files most likely to attract "I'll just tweak this"
edits from five directions at once. Giving them a single owner converts a
six-way merge problem into a conversation.

### Why M6 owns two frontend files

`api.js` and `map.js` are libraries with fixed public interfaces, not screens.
M5 calls `EFR.api.mock()` and `EFR.map.plot()` and never opens either file. That
lets M5 own the entire visual surface without either person waiting.

---

## 2. The seven rules

**1 · Never edit a file you do not own.** Not even a typo. Not even a one-line
fix that is "obviously right". Message the owner instead.

**2 · Need a change in someone else's file? Ask, don't edit.** Post
`CONTRACT CHANGE REQUEST: <field/function> — <why>` in the group. M6 makes the
change in one commit and announces it. Total cost: two minutes. Cost of editing
it yourself: an hour of merge archaeology at 1am.

**3 · The contract is frozen at end of Day 1 morning.** Before the freeze,
changes are cheap — argue about field names *now*. After it, additive changes
only (see `API_CONTRACT.md` §8).

**4 · Return plain dicts matching the contract.** Do not import another
member's module. Do not import Pydantic in your module. `pipeline.py` calls you
and `schemas.py` validates the result; that is the only coupling that exists.

**5 · Never raise into the pipeline.** Malformed input is data, not an error.
Return the contract-shaped empty value for the part you could not compute.
`pipeline.py` guards every call anyway, but a module that degrades gracefully
gives a partial answer while one that raises gives none.

**6 · Flip your `IS_STUB = False` flag when your module actually works.** It
drives `module_status` in the API response and the live/stub chips in the UI
header — the whole team can see build progress at a glance, and the demo can
honestly show what is finished.

**7 · Run the contract tests before every commit.**
```
python -m pytest backend/tests/test_contract.py -q
python scripts/verify_contract.py            # stdlib only, needs no install
```
These pass against pure stubs and must keep passing as you fill your module in.
If they break, you broke a boundary — fix it before pushing, not after.

`verify_contract.py` runs the whole pipeline over every sample and compares the
response shape against the frozen fixture, key by key. It catches the failure
mode that hurts most: a module quietly returning a differently-shaped dict, which
tests with hand-written inputs will never notice. It also flags *undocumented
extra keys* — if you add a field, the contract and the fixture have to learn
about it too, so tell M6 rather than silencing the check.

---

## 3. Git workflow

```bash
git checkout -b feat/m3-confidence      # branch per member, per feature
# ... work only inside your own files ...
python -m pytest backend/tests -q
git add backend/app/intel/ backend/tests/test_m3_intel.py
git commit -m "M3: confidence demotion model + reasons"
git push -u origin feat/m3-confidence   # M6 merges to main
```

`git add .` is banned. Add your own paths explicitly — it is the habit that
stops you accidentally committing someone else's half-finished file, or a 4 MB
GeoLite2 database, or your `.env`.

**No git at all?** The ownership split still saves you: zip up only your own
folder and let M6 copy files into place. Nothing overwrites anything.

`requirements.txt` is the one shared file. It has a pre-allocated commented
block per member — add your line inside your block only, and never reorder the
file. Append-only edits to distinct regions merge cleanly every time.

---

## 4. Dependency graph — and why nobody waits

```
                    ┌─────────────────────────────┐
                    │  M6: contract + fixture     │  Hour 0-2. Blocks nobody
                    │  (schemas, pipeline, mock)  │  after it lands.
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────┬───────────┼───────────┬──────────────┐
        ▼              ▼           ▼           ▼              ▼
    ┌───────┐     ┌───────┐   ┌───────┐   ┌───────┐     ┌────────┐
    │  M1   │     │  M2   │   │  M3   │   │  M4   │     │   M5   │
    │parser │     │auth + │   │geo +  │   │report │     │  UI    │
    │       │     │rank   │   │conf   │   │+ hash │     │        │
    └───────┘     └───────┘   └───────┘   └───────┘     └────────┘
    all five work simultaneously against the CONTRACT, never against each other
```

The only real dependency is M6's contract, and it exists within the first two
hours. After that:

- **M2** needs M1's `received_chain` — but codes against the documented shape and
  tests with hand-written hop dicts (see `test_m2_auth_ranking.py`, which already
  contains one).
- **M3** needs M2's `ip_candidates` — same story, and `GEOIP_PROVIDER=mock` makes
  the geo path deterministic and offline.
- **M4** needs a full analysis dict — uses `fixtures/sample_response.json`.
- **M5** needs the API — uses `GET /api/v1/mock/analyze`, which works before any
  backend logic exists.

Nobody says "I'm blocked on X". If you feel blocked, you are missing a fixture,
and building the fixture is the fix.

---

## 5. Two-day schedule

### Day 1

| When | M1 | M2 | M3 | M4 | M5 | M6 |
|---|---|---|---|---|---|---|
| **Hour 0–2** | Read contract. Set up venv. Run the stub pipeline once. | ← same | ← same | ← same | ← same | **Contract + fixture + pipeline. Announce the freeze.** |
| **Morning** | Headers, mailboxes, subject decode, dates | Parse `Authentication-Results`, `verified_by`, `self_asserted_only` | `lookup_ip` mock path + `classify_infrastructure` | `canonical_evidence_hash` + custody log append/verify | HTML shell + CSS + wire `btn-sample` to `EFR.api.mock()` | Wire routes, get `/analyze` returning stub JSON end-to-end |
| **Afternoon** | Received chain — **hop 1 = closest to sender** — + integrity | `rank_ip_candidates` trust tiers + private-IP exclusion | `assess_confidence` demotion ladder + `build_origin` | `build_report_payload` sections | Verdict + auth + signal panels | Collect real `.eml` samples; run all six through the pipeline |
| **Evening** | Anomaly codes | Real ip-api call path + fallback | `score_risk` all five signals | JSON report served from the API | Origin panel + map wiring | **Integration checkpoint: every sample runs, `test_contract.py` green** |

**End of Day 1 must-have:** paste an email, get real parsed JSON on screen, with
a confidence label. Ugly is completely fine. If this does not work by the end of
Day 1, cut PDF export and the map before cutting anything else.

### Day 2

| When | Focus |
|---|---|
| **Morning** | M1/M2 fix edge cases against real samples · M3 tune weights · M4 PDF (only if JSON is done) · M5 polish + map confidence labels · M6 run the full sample matrix |
| **Afternoon** | **Confidence matrix verification** — every sample in `samples/README.md` must produce its expected label. This is the acceptance gate for the whole project. Then edge cases: no headers, private IPs only, missing SPF, malformed chains, non-UTF8, huge files. |
| **Evening** | Freeze code. Rehearse the demo three times end to end. Finalise slides. Everyone memorises the judge statement (`API_CONTRACT.md` §6 and the pitch notes). |

---

## 6. Definition of done — the whole project

Tick these, in this order. Anything below the line is optional.

- [ ] `python -m pytest backend/tests -q` — all green
- [ ] All six samples run without an exception
- [ ] `01_high_confidence_direct.eml` → confidence **high**
- [ ] `02_spoofed_paypal_hosted.eml` → confidence **medium**, band **critical**
- [ ] `03_vpn_exit_low_confidence.eml` → confidence **low**
- [ ] `04_webmail_no_origin_ip.eml` → confidence **low** *despite all auth passing*
- [ ] `06_minimal_no_headers.eml` → no-origin path, no crash
- [ ] Every map pin shows a confidence label
- [ ] Origin statement appears verbatim in the UI *and* the report
- [ ] Report downloads and its SHA-256 verifies
- [ ] Custody chain verification detects a hand-edited log
- [ ] All six `IS_STUB` flags are `False`
- [ ] Demo rehearsed end to end at least twice

— optional below this line —

- [ ] PDF export
- [ ] Offline GeoLite2 fallback
- [ ] Deployment to Render/Railway

---

## 7. Failure protocol

If something is not working two hours before a milestone, **say so immediately**
in the group. The whole architecture is designed so that a failing module
degrades one panel instead of the demo. What breaks a demo is a person quietly
struggling until it is too late to route around them.

A module that stays a stub is a known, contained, honestly-labelled gap. A
module that half-works and raises unpredictably is worse than a stub, because
you cannot demo around it. If you run out of time, revert to the stub and flag
it — `module_status` will show it, the UI will grey the panel, and the demo
survives.
