# M6 — Integration, contract, samples & pitch

You are not the person who writes the least code. You are the person whose work
determines whether five people's code fits together, and you are the reason
nobody on this team ever says "I'm blocked."

Your first two hours are the highest-leverage hours anyone on the team will
spend. Everything after that is guarding the boundaries and building the demo.

**Read first:** all of `API_CONTRACT.md` — you own it.

---

## Your files

```
API_CONTRACT.md                    the frozen contract (you are its sole editor)
backend/app/schemas.py             Pydantic models = executable contract
backend/app/pipeline.py            orchestrator, guards every module call
backend/app/main.py                FastAPI routes
backend/app/core/config.py         shared config + trusted-provider lists
frontend/js/api.js                 API client
frontend/js/map.js                 Leaflet module
fixtures/sample_response.json      the frozen mock
samples/                           the .eml corpus
backend/tests/test_contract.py     contract conformance
scripts/verify_contract.py         stdlib-only shape check over all samples
backend/tests/test_m6_api.py       API tests
pitch/                             slides + demo script
```

Everything above is already scaffolded and compiles. Your job on Day 1 hour 0 is
to **verify it**, then hold the line.

## Why you own the two frontend files

`api.js` and `map.js` are libraries with fixed public interfaces, not screens.
M5 calls `EFR.api.mock()` and `EFR.map.plot()` and never opens either. That lets
M5 own the entire visual surface while you own the glue — two people on the
frontend, zero shared files.

---

## Hour 0–2: the only thing that blocks anyone

1. Everyone clones. `bash scripts/run_backend.sh` → confirm
   `http://127.0.0.1:8000/docs` loads.
2. `python -m pytest backend/tests -q` → confirm green against pure stubs.
3. `curl http://127.0.0.1:8000/api/v1/mock/analyze` → confirm the fixture returns.
   Also run `python scripts/verify_contract.py` — no install needed, so this one
   works even on the teammate whose venv is broken.
4. **Walk the whole team through `API_CONTRACT.md` §3 out loud.** Fifteen minutes.
   Argue about field names *now*, while it is free.
5. Announce: **"CONTRACT v1.0 FROZEN"**.

After that announcement, five people can work in parallel indefinitely without
talking to each other. That is the entire point of your role.

## Guarding the contract

You are the only person who edits `schemas.py`, `pipeline.py`, or
`API_CONTRACT.md`. When a change request arrives:

1. Decide: additive (cheap, say yes) or breaking (after Day 1 midday, almost
   certainly no — add a new field and leave the old one populated).
2. Edit `API_CONTRACT.md` **and** `schemas.py` **and**
   `fixtures/sample_response.json` in **one commit**. All three or none — a
   fixture that disagrees with the schema is worse than no fixture, because it
   silently teaches M5 the wrong shape.
3. Bump `schema_version`, announce `CONTRACT v1.1 LIVE`, tell everyone to pull.

When someone asks to change a contract field because their implementation is
awkward, the usual right answer is to fix the implementation. The contract exists
so that five people's assumptions stay compatible; bending it to suit one module
invalidates four other people's completed work.

## The samples corpus

Six synthetic samples are already in `samples/` with a coverage table in
`samples/README.md`. Your job is to **add real ones** — and to make sure the set
still covers every confidence branch.

Where to get genuine material: your own spam folders (six people, six inboxes),
your college IT helpdesk, or public corpora (Nazario phishing corpus, PhishTank).
Strip your own address and any personal data; keep the `Received` chain intact —
that is the evidence.

**Sample 04 is the one to understand deeply.** Gmail-sent, all authentication
passes, and the only IP is Google's outbound relay. It is the case that catches
naive implementations: a scorer keyed on auth calls it clean, but we know nothing
about the sender's location. It must produce **low** confidence. If your build
says `high` there, the confidence model is broken — and this is exactly the case
a knowledgeable judge will probe.

## Integration checkpoints — run these, don't assume

**Day 1 evening.** Every sample through `/api/v1/analyze`, `test_contract.py`
green, frontend renders real output.

**Day 2 afternoon — the confidence matrix.** This is the acceptance gate for the
whole project:

| Sample | Expected confidence | Expected band |
|---|---|---|
| 01 direct, clean auth | **high** | low |
| 02 spoofed, hosted IP | **medium** | critical |
| 03 VPN exit, BEC wording | **low** | critical |
| 04 webmail, auth all pass | **low** | medium |
| 05 broken chain | **low** | high |
| 06 no headers | **low** | medium |

Every row must match. If one doesn't, that is M3's confidence ladder or M2's
ranking, and it is a bug — not a judgement call to wave through.

Then the edge cases: empty input, 5 MB file, `.exe` upload, non-UTF8 bytes,
headers-only with no body, a message with 40 hops.

---

## The pitch

### Demo script — 4 minutes, rehearsed three times

**0:00 – 0:30 · Frame the problem.** A cybercrime cell receives a reported
phishing email. An analyst spends hours manually reading headers, checking auth,
looking up IPs, and writing it up. We compress that into a minute — and, crucially,
without overstating what the evidence supports.

**0:30 – 1:30 · Sample 01, the clean case.** Paste, analyze. Point at the low risk
score, the green auth badges, the **high** confidence origin. Establish that the
tool can say "this looks fine."

**1:30 – 2:45 · Sample 02, the spoof.** Paste, analyze. Walk the score breakdown:
auth failed, Reply-To goes to a different country, the IP is a rented
DigitalOcean box. Then the money moment — the ranked candidate list:

> "Three IPs appear in these headers. We didn't take the first one. We ranked
> them by who recorded them. This one was written down by Google's own receiving
> server, so we trust it most. This one is an internal private address, so we
> excluded it and we show you why."

Then: **medium** confidence, and read the statement aloud.

**2:45 – 3:30 · Sample 04, the one that makes the point.** Every auth check
passes. Green across the board. And confidence is **low** — because the only IP
in the headers is Gmail's relay.

> "Authentication passing tells us the domain wasn't spoofed. It tells us nothing
> about where the sender was. A tool that conflated those two would give you false
> confidence, so ours doesn't."

That is the moment a knowledgeable judge decides you know what you're doing.

**3:30 – 4:00 · Report + custody.** Download the report. Show the SHA-256. Show
`custody-log` → `intact: true`. Edit one character in the log file live. Refresh →
`intact: false, broken_at: 2`.

### The question you will definitely get

*"So can you actually catch the attacker?"*

Answer with `API_CONTRACT.md` §6 / the problem statement's §3.6 wording, close to
verbatim. **Everyone on the team memorises this** — if two members answer it
differently, the inconsistency does more damage than either answer:

> "If an attacker uses a VPN or multiple relay servers, we do not claim that the
> IP location is their real physical location. Our platform identifies the most
> credible visible infrastructure, detects anonymization or hosting indicators,
> assigns a confidence level, and preserves the IP, timestamps, routing chain,
> authentication failures, and message identifiers. This supports campaign
> correlation and lawful follow-up with relevant providers. Our goal is
> defensible forensic intelligence, not false certainty."

Then pivot to the roadmap: Phase 2 adds the ML classifier, Phase 3 adds cross-case
attribution graphs. This shows the scoping was deliberate, not something you ran
out of time for.

### Other likely questions

**"Why no machine learning?"** Two days, and explainability. Every point on our
score traces to a named rule with the exact evidence that triggered it, which an
analyst can defend in a report. Phase 2 adds a classifier trained on the Nazario
corpus to augment — not replace — the rule engine.

**"Why not re-check SPF via DNS yourself?"** A result recorded by the receiving
MTA at delivery time is stronger evidence than one we recompute later against DNS
that may have changed. Re-querying would weaken the evidence, not strengthen it.

**"Is this a blockchain?"** No — it's a hash chain in an append-only log, which is
the primitive that actually provides tamper-evidence. We didn't need distributed
consensus for a single-analyst workflow. (Answering this precisely is worth more
than claiming blockchain.)

**"How did you validate the risk weights?"** Honestly: they reflect
analyst-assigned severity, calibrated against our sample corpus. We have not
measured accuracy on a held-out set — that's Phase 2, with the labelled public
datasets.

### Slides — 6, no more

1. Problem: manual email forensics is slow and inconsistent
2. What we built: the pipeline diagram, one arrow per module
3. The confidence model — the differentiator, and the one slide to spend time on
4. Live demo (no slide, just the app)
5. Forensic report + chain of custody
6. Roadmap Phases 2–6, with Phase 1 ticked

Put the honest-limitations table (problem statement §3.2) on slide 3. Volunteering
the limitation is what makes the rest of the claims credible.

---

## Definition of done

- [ ] `python -m pytest backend/tests -q` green
- [ ] `python scripts/verify_contract.py` exits 0 with zero stub-related nulls
- [ ] Confidence matrix above: all six rows match
- [ ] Every edge case returns a structured error, never a stack trace
- [ ] Frontend works against the real backend end to end
- [ ] All six `IS_STUB` flags are `False`
- [ ] Demo rehearsed three times, under 4 minutes
- [ ] Whole team can recite the attribution answer consistently
- [ ] Slides finalised
- [ ] Laptop tested on the actual projector, offline mode verified

## Traps

**Don't let a change request go in silently.** One undocumented field rename
costs five people an hour each.

**Don't let the fixture drift from the schema.** They must change in the same
commit or M5 is building against a lie.

**Have an offline story.** Venue wifi will fail. `GEOIP_PROVIDER=mock` plus
`DEMO_MODE=true` gives you a demo that works with no network at all. Test that
path on Day 2 — not on stage.

**Don't be the bottleneck you were meant to prevent.** If you're deep in your own
code when someone needs a contract decision, answer them first. Unblocking five
people beats finishing your own task.
