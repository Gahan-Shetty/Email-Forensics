# M4 — Forensic report & chain of custody

You produce the artefact that leaves the building. Everything else lives on a
screen for ninety seconds; your report is the thing a judge could imagine
attaching to an actual complaint. That framing should drive every layout choice
you make.

**Read first:** `API_CONTRACT.md` §3 (the `report` block), §6 (the wording you
must reproduce verbatim), §7 (your signatures).

---

## Your files

```
backend/app/report/report_builder.py    build_report_payload(), canonical_evidence_hash()
backend/app/report/custody_log.py       append_custody_entry(), read_custody_log(), verify_custody_chain()
backend/app/report/pdf_renderer.py      render_pdf()
backend/tests/test_m4_report.py         your tests
```

**Never open:** anything in `parsing/`, `intel/`, `frontend/`, `schemas.py`,
`pipeline.py`, `main.py`.

You are the least blocked person on the team: your input is a complete analysis
dict, and `fixtures/sample_response.json` is one, sitting on disk, right now.
You can be finished before anyone else's module works.

---

## Priority order — this matters more than anything else on this page

1. `canonical_evidence_hash()` — twenty minutes, and everything else depends on it
2. `custody_log.py` — the tamper-evidence story, and the best live demo moment in the project
3. `build_report_payload()` — the JSON report, which **fully satisfies the deliverable on its own**
4. `render_pdf()` — **only after 1–3 are done and tested**

PDF layout is the single easiest place in this project to lose four hours to
nothing. If it is Day 2 afternoon and the PDF is not working, ship JSON and say
*"PDF export is wired but we prioritised evidence integrity."* That is a good
answer, delivered from a position of strength. A half-finished PDF that raises
mid-demo is not.

---

## Part 1 — `canonical_evidence_hash()`

```python
payload = {k: v for k, v in analysis.items() if k not in HASH_EXCLUDED_TOP_LEVEL}
blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                  ensure_ascii=True, default=str)
return hashlib.sha256(blob.encode("utf-8")).hexdigest()
```

This is already written for you. What matters is understanding **why each
argument is there**, because you will be asked:

- `sort_keys=True` — dict ordering must not change the hash. Without it, the same
  evidence hashes differently on different runs and the tamper-evidence claim is
  worthless.
- `separators=(",", ":")` — no incidental whitespace in the hashed bytes.
- `HASH_EXCLUDED_TOP_LEVEL` — `timings_ms`, `report`, `module_status` change
  between runs for reasons that are not evidence. Hashing them would make
  verification always fail, which is worse than not verifying.
- `default=str` — never raise on an unexpected type mid-hash.

Your first two tests (`test_hash_is_stable_across_key_order`,
`test_hash_ignores_volatile_fields`) already pass against the stub. Run them now
and confirm.

## Part 2 — `custody_log.py`

Append-only JSONL. Each entry stores the hash of the previous entry, so altering
or deleting any past entry breaks the chain detectably.

```python
entry = {
    "entry_no": n,
    "recorded_at": iso_utc_now(),
    "analysis_id": analysis_id,
    "evidence_sha256": evidence_sha256,
    "report_id": f"RPT-{yyyymmdd}-{n:04d}",
    "actor": "local-analyst",
    "meta": meta,
    "previous_entry_hash": prev_hash,   # None for entry 1
}
entry["entry_hash"] = _entry_hash(entry)   # excludes entry_hash itself
```

`_entry_hash()` must exclude the `entry_hash` key — you cannot hash a field that
does not exist yet. Same canonical-JSON technique as above.

**Say "hash chain in an append-only log", not "blockchain".** It is the actual
primitive that provides tamper-evidence, and a hash chain is genuinely what a
blockchain uses for its ledger — minus distributed consensus, which we have no
need for. Claiming blockchain for a local JSONL file invites a question you will
lose; describing it accurately invites one you will win.

### The demo moment — rehearse this

Thirty seconds, and it lands harder than any slide:

1. `GET /api/v1/custody-log` → `"intact": true`
2. Open `evidence/custody_log.jsonl` in an editor in front of the judges, change
   one character, save
3. `GET /api/v1/custody-log` again → `"intact": false, "broken_at": 2`

`test_tampering_breaks_the_chain` in your test file verifies this works before
you attempt it live. Run it first.

### Never raise into the request path

If the log write fails: log a warning, return `(0, None)`, let `pipeline.py` add
the `warnings` entry. A failed custody write must not lose the analysis the user
just waited for.

## Part 3 — `build_report_payload()`

Eight sections, in this order — it mirrors how a real forensic exhibit reads,
which is most of why the output feels credible:

| § | Section | Contents |
|---|---|---|
| 1 | Case header | `report_id`, `generated_at` (UTC Z), `analysis_id`, tool name + version, input SHA-256, filename, byte size |
| 2 | Summary | Risk score + band + verdict, and `origin["statement"]` **verbatim** |
| 3 | Sender identity | From / Reply-To / Return-Path / Message-ID + M1's anomaly list |
| 4 | Authentication | SPF / DKIM / DMARC with raw header text and `verified_by`. Flag `self_asserted_only` loudly |
| 5 | Routing | The full `received_chain` as an ordered table: hop / timestamp / from_host / from_ip / by_host / TLS |
| 6 | Origin analysis | Selected IP, geo, `infrastructure_type`, confidence, and **every** `confidence_reason` as a bullet |
| 7 | Limitations | `LIMITATIONS_TEXT` — already written, use it complete |
| 8 | Integrity | `evidence_sha256`, custody entry number, previous entry hash |

`report_id` format: `RPT-YYYYMMDD-NNNN` where `NNNN` is the zero-padded custody
entry number. Sortable, human-readable, and shaped like a real case reference.

### Section 7 is not padding

`LIMITATIONS_TEXT` is what makes the document defensible. A report that states
what it cannot prove is a report someone can act on; one that overclaims gets
thrown out at the first cross-examination. Do not trim it to make the PDF fit on
one page — let it run to page two.

Same for section 6: print **every** `confidence_reason`, not the first two. The
reasons are why the confidence label is credible.

## Part 4 — `render_pdf()` (last)

```python
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet
```

Build a `story` list and append in the payload's section order. Use `Table()` for
the routing chain and auth results — it handles column widths for you and looks
far more forensic than paragraphs. Put the risk band colour behind the score cell
with a `TableStyle` `BACKGROUND` command; `BAND_COLOURS` in your file matches
M5's CSS palette so the PDF and the screen agree.

**Escape user-supplied text before it reaches `Paragraph()`:**

```python
from xml.sax.saxutils import escape
Paragraph(escape(subject or ""), styles["Normal"])
```

reportlab interprets `Paragraph` content as markup, so a bare `&` or `<` in a
real phishing subject line raises. This *will* happen with a real sample — escape
from the start rather than debugging it later.

---

## Definition of done

- [ ] `python -m pytest backend/tests/test_m4_report.py -q` green
- [ ] Same analysis hashed twice with shuffled key order → identical hash
- [ ] Changing `timings_ms` → hash unchanged
- [ ] Changing `origin.selected_ip` → hash changes
- [ ] Custody entries increment; entry 1 has `previous_entry_hash: null`
- [ ] Hand-editing the log → `verify_custody_chain()` reports `intact: false` and the right `broken_at`
- [ ] `origin["statement"]` appears verbatim in the report
- [ ] All `LIMITATIONS_TEXT` items present
- [ ] Every `confidence_reason` present
- [ ] JSON report downloads from `/api/v1/report/{id}.json`
- [ ] `IS_STUB = False` in `report_builder.py` and `custody_log.py`

## Traps

**`json.dumps` on a `datetime`** raises without `default=str`. Already handled —
don't remove it.

**Hashing `report` inside the report** is circular. It is in the exclusion list.

**Sample 06 has almost no data.** `build_report_payload` must handle `None`
everywhere — no `KeyError`, no `NoneType has no attribute`. Test with sample 06
early, not at the end.

**Don't add a database.** In-memory `_STORE` in `main.py` is deliberate (see the
tech-stack table). Persistence is Phase 4. Adding SQLite "quickly" on Day 2 is
how a working demo becomes a broken one.
