# SIH26106 — Email Threat Detection, Geolocation & Forensic Intelligence

**MVP:** Email Header Forensic Analyzer with confidence-scored geolocation and a
downloadable forensic report.

Paste raw email headers (or upload a `.eml`) and get back: a parsed header
summary, the reconstructed `Received` routing chain, SPF/DKIM/DMARC results as
recorded by the receiving server, a **ranked** list of candidate origin IPs with
a trust tier for each, a geolocation with an explicit **high / medium / low**
confidence label, a 0–100 rule-based risk score with per-signal breakdown, and a
JSON + PDF report with a SHA-256 evidence hash written into a tamper-evident
chain-of-custody log.

The design principle throughout: **never claim more than the headers support.**
A VPN exit node or a webmail relay is reported as exactly that, and confidence is
demoted accordingly.

---

## Quick start

```bash
# backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
bash scripts/run_backend.sh        # Windows: scripts\run_backend.bat
# → http://127.0.0.1:8000/docs

# frontend (separate terminal — must be served over HTTP, not file://)
bash scripts/run_frontend.sh       # Windows: scripts\run_frontend.bat
# → http://127.0.0.1:5500
```

Sanity checks:

```bash
python -m pytest backend/tests -q
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:8000/api/v1/mock/analyze     # works with zero logic implemented
python scripts/verify_contract.py                  # structural check, no deps needed
```

`/api/v1/mock/analyze` returns `fixtures/sample_response.json` unconditionally.
That endpoint is what lets the frontend and report modules be built before any
parsing logic exists.

---

## Read these, in this order

| # | File | Who |
|---|---|---|
| 1 | [`docs/00-TEAM-PLAN.md`](docs/00-TEAM-PLAN.md) | **everyone, first** — ownership map + the seven conflict rules |
| 2 | [`API_CONTRACT.md`](API_CONTRACT.md) | **everyone** — the frozen JSON shape and function signatures |
| 3 | `docs/0N-MN-*.md` | your own module doc |

| Member | Scope | Doc |
|---|---|---|
| M1 | Header parsing + Received chain | [`01`](docs/01-M1-header-parsing.md) |
| M2 | SPF/DKIM/DMARC + IP trust ranking | [`02`](docs/02-M2-auth-and-ip-ranking.md) |
| M3 | Geolocation, confidence model, risk score | [`03`](docs/03-M3-geo-confidence-scoring.md) |
| M4 | Report builder, PDF, chain of custody | [`04`](docs/04-M4-report-and-custody.md) |
| M5 | Frontend UI + rendering | [`05`](docs/05-M5-frontend.md) |
| M6 | Contract, pipeline, API, samples, pitch | [`06`](docs/06-M6-integration-and-pitch.md) |

---

## How the parallel build works

Every module is scaffolded as a **runnable stub**: correct signature, correct
return shape, `IS_STUB = True` at the top of the file. The pipeline already runs
end to end and the API already answers. Each member replaces the body of their
own functions and flips `IS_STUB = False`.

Three mechanisms keep six people out of each other's way:

**One file, one owner.** The territories in `00-TEAM-PLAN.md` do not overlap. If
you need something changed in someone else's file, ask them — do not edit it.

**The contract is executable.** `backend/app/schemas.py` is the Pydantic
translation of `API_CONTRACT.md`. Drift from the agreed shape fails loudly at the
API boundary instead of silently reaching the UI.

**Nobody waits.** The frozen fixture unblocks M5 and M4 on hour one, and M2/M3's
tests use hand-written input dicts so they don't depend on M1 finishing.

`pipeline.py` wraps every module call individually. An unfinished or crashing
module degrades exactly one block of the response to null/stub plus a `warnings`
entry — it never takes down the request.

---

## Layout

```
API_CONTRACT.md          frozen JSON contract + function signatures   (M6)
docs/                    team plan + one implementation doc per member
backend/app/
  parsing/               header_parser, received_chain               (M1)
                         auth_checks, ip_ranking                    (M2)
  intel/                 geoip, confidence, risk_score              (M3)
  report/                report_builder, custody_log, pdf_renderer  (M4)
  pipeline.py main.py schemas.py core/config.py                     (M6)
backend/tests/           test_contract.py must stay green always
frontend/                index.html, css/, js/render.js, js/app.js   (M5)
                         js/api.js, js/map.js                       (M6)
fixtures/                sample_response.json — the frozen mock      (M6)
samples/                 six .eml files covering every branch        (M6)
evidence/                generated reports + custody log (gitignored)
```

## Stack

Python 3.10+ · FastAPI · stdlib `email` for parsing · ip-api.com free tier with
MaxMind GeoLite2 fallback · reportlab for PDF · hashlib SHA-256 for custody ·
vanilla HTML/CSS/JS + Leaflet.js, no build step · no database (append-only JSONL).

## Scope — deliberately out for the hackathon

No ML classifier, no attachment sandboxing, no live threat-intel feeds, no
cross-case correlation graph, no inbox monitoring. These are Phases 2–6. The
rule-based engine was chosen over ML because every point of the score traces to a
named signal with the evidence that triggered it — which is what makes a forensic
report defensible.

## Honesty about attribution

This platform identifies the most credible **visible sending infrastructure** and
labels how much that is worth. It does not claim to locate a human being. When
anonymization is detected, that is reported as a finding rather than hidden behind
a confident-looking pin on a map. See `API_CONTRACT.md` §6 for the required
wording, which is not paraphrasable.
