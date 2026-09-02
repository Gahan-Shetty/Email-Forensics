# M5 Frontend --- Full Backend Integration Correction & Verification Specification

**Project:** SIH26106 --- Email Threat Detection, Geolocation & Forensic
Intelligence\
**Module:** M5 --- Frontend UI + Rendering\
**Purpose:** Correct frontend integration problems so the existing UI
works smoothly with the real FastAPI backend.

------------------------------------------------------------------------

## 1. Scope and Non-Negotiable Rules

### Primary goal

Make the existing frontend function as a real client for the backend,
using the frozen API contract and the actual FastAPI endpoints.

### Do NOT change

-   The current visual style, theme, animations, layout, colors, or
    branding.
-   Existing user-facing wording, labels, explanatory text, forensic
    wording, or footer text unless a value is technically wrong because
    of an API mapping issue.
-   The current design direction or UI concept.
-   Backend files owned by M1, M2, M3, M4, or M6.
-   `API_CONTRACT.md` to compensate for frontend mistakes.

This task is an **integration correction**, not a redesign.

------------------------------------------------------------------------

# 2. Canonical Runtime Architecture

The intended local development setup is:

``` text
Browser
   |
   | opens
   v
Frontend server
http://127.0.0.1:5500
   |
   | fetch()
   v
FastAPI backend
http://127.0.0.1:8000
   |
   v
/api/v1/...
```

The frontend must never accidentally send API requests to port `5500`
merely because `API_BASE` is empty.

------------------------------------------------------------------------

# 3. Critical Issue: API Route Mismatch

The frontend previously used routes that did not match the FastAPI
backend.

## Incorrect frontend routes

``` text
/api/analyze
/health
/api/custody
/api/reports/{id}
```

## Required backend routes

``` text
POST /api/v1/analyze
GET  /api/v1/health
GET  /api/v1/custody-log
GET  /api/v1/report/{analysis_id}.json
GET  /api/v1/report/{analysis_id}.pdf
```

### Required frontend behavior

All frontend API calls must be constructed from one consistent backend
base URL.

For local development:

``` text
http://127.0.0.1:8000
```

Therefore, the effective requests must be:

``` text
http://127.0.0.1:8000/api/v1/analyze
http://127.0.0.1:8000/api/v1/health
http://127.0.0.1:8000/api/v1/custody-log
http://127.0.0.1:8000/api/v1/report/{analysis_id}.json
http://127.0.0.1:8000/api/v1/report/{analysis_id}.pdf
```

### Recommendation

Centralize the API base URL in `frontend/js/api.js`.

Do not scatter `127.0.0.1:8000` throughout rendering code.

If environment/config support already exists, use that mechanism rather
than introducing a second configuration system.

------------------------------------------------------------------------

# 4. Critical Issue: Wrong Analyze Request Format

The frontend previously sent the analysis request as raw `text/plain`.

That is incompatible with the JSON request path used by the backend.

## Required JSON request

``` json
{
  "raw_email": "raw email/header content"
}
```

The request must use:

``` text
Content-Type: application/json
```

Conceptually:

``` javascript
fetch(API_BASE + "/api/v1/analyze", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    raw_email: rawEmail
  })
})
```

### Important

Do not change the backend endpoint merely to accept an incorrect
frontend format.

The frontend must conform to the frozen backend contract.

------------------------------------------------------------------------

# 5. `.eml` Upload Support Must Match Backend Expectations

The project description says users can paste raw headers **or upload an
`.eml` file**.

If the current UI exposes file upload, verify that the upload request
uses the format expected by the FastAPI endpoint.

Do not send a JavaScript string pretending to be an uploaded file.

If the backend expects multipart upload, use:

``` text
multipart/form-data
```

with `FormData`.

Do not manually set the multipart `Content-Type`; the browser must set
the boundary.

Verify both flows:

1.  Paste raw email/header text.
2.  Upload a real `.eml` file.

Both should reach the real backend and produce an analysis response.

------------------------------------------------------------------------

# 6. Critical Issue: Silent Mock Fallback

The previous frontend API client contained a dangerous behavior:

``` text
Live backend request fails
        ↓
Frontend silently catches error
        ↓
Sample/mock fixture is returned
        ↓
UI looks successful even though integration failed
```

This caused false confidence during testing.

## Required behavior

When the user explicitly performs a real analysis:

-   If the backend is available and succeeds → render real backend data.
-   If the backend returns an HTTP error → show an understandable UI
    error.
-   If the network fails → show an understandable connection error.
-   Do not silently substitute sample data.

### Mock/demo data

Mock data may still exist if it is intentionally used for an explicit
demo mode or "load demo" action.

However, it must be clearly separated from real analysis.

A user must never submit an email, receive a failed backend request, and
unknowingly see fake analysis results.

### Acceptance test

Stop the backend and submit an email.

Expected:

``` text
Visible backend/connection error
```

Not expected:

``` text
A successful-looking forensic analysis generated from fixtures
```

------------------------------------------------------------------------

# 7. Critical Issue: Renderer Schema Mismatches

The frontend renderer must consume the actual API response shape.

Do not invent alternate field names.

## 7.1 Authentication alignment field

### Incorrect

``` text
from_matches_return_path
```

### Required

``` text
from_vs_returnpath_match
```

The renderer must read the field defined by the backend contract.

------------------------------------------------------------------------

## 7.2 Origin GeoIP metadata

The frontend previously attempted to read values directly from `origin`.

### Incorrect examples

``` text
origin.isp
origin.asn
origin.is_datacenter
origin.is_proxy
origin.is_mobile
```

### Required structure

These values are inside:

``` text
origin.geo
```

Examples:

``` text
origin.geo.isp
origin.geo.asn
origin.geo.is_datacenter
origin.geo.is_proxy
origin.geo.is_mobile
```

The UI should safely handle missing geo data without throwing JavaScript
errors.

For example:

``` text
origin.geo may be null or incomplete
```

Missing optional intelligence should display the existing
neutral/unknown representation, not crash the page.

------------------------------------------------------------------------

## 7.3 Risk signal title

The backend risk signal object uses:

``` text
label
```

The frontend previously used:

``` text
name
```

Required mapping:

``` text
s.label
```

If backward compatibility is intentionally desired, a safe fallback may
be used:

``` text
s.label || s.name
```

However, the primary live-contract field must be `label`.

------------------------------------------------------------------------

# 8. Defensive Rendering Requirements

The backend is designed to degrade gracefully when some intelligence is
unavailable.

The frontend must behave the same way.

Do not assume that every nested object always exists.

Examples that must not crash rendering:

-   `origin` partially populated.
-   `origin.geo` missing or null.
-   No credible origin IP.
-   Empty `ip_candidates`.
-   Empty `received_chain`.
-   Missing optional geolocation fields.
-   Empty confidence reasons.
-   Minimal email with limited forensic evidence.
-   Module warnings present.

Use safe access and existing UI placeholders while preserving the
current design.

The goal is:

``` text
Missing forensic data → reduced information shown

NOT

Missing forensic data → JavaScript exception / broken dashboard
```

------------------------------------------------------------------------

# 9. `analysis_id` Must Flow Through the Whole Frontend

A successful analysis response provides an `analysis_id`.

That exact ID must be preserved and reused for report retrieval.

Required flow:

``` text
POST /api/v1/analyze
        |
        v
Receive analysis_id
        |
        +--> GET /api/v1/report/{analysis_id}.json
        |
        +--> GET /api/v1/report/{analysis_id}.pdf
```

Do not generate a new ID in the frontend.

Do not confuse `report_id` with `analysis_id` unless the backend
contract explicitly requires a different value for a specific operation.

------------------------------------------------------------------------

# 10. Report JSON and PDF Integration

Verify the frontend constructs the exact report URLs.

## JSON

``` text
GET /api/v1/report/{analysis_id}.json
```

## PDF

``` text
GET /api/v1/report/{analysis_id}.pdf
```

Expected behavior:

-   JSON report retrieval succeeds for a real analysis.
-   PDF endpoint returns/downloads the generated PDF.
-   The frontend does not use an invented `/api/reports/...` path.
-   The analysis ID used is the one returned by the real backend.

------------------------------------------------------------------------

# 11. Custody Log Integration

The backend endpoint is:

``` text
GET /api/v1/custody-log
```

The frontend must not use:

``` text
/api/custody
```

If custody information is rendered, verify that the response shape is
consumed according to the actual contract.

Missing or temporarily empty custody data must not crash the page.

------------------------------------------------------------------------

# 12. Health Check Integration

Use:

``` text
GET /api/v1/health
```

The health check should be useful for detecting whether the real backend
is reachable.

Do not use a health check that accidentally targets the frontend server
on port `5500`.

------------------------------------------------------------------------

# 13. Frontend Directory Structure --- Important Design/Integration Issue

The integration audit found two parallel frontend structures:

``` text
Repository root
├── index.html
├── js/
└── css/
```

and:

``` text
frontend/
├── index.html
├── js/
└── css/
```

The frontend run script serves the `frontend/` directory.

This creates a major risk:

``` text
Developer edits root files
        ↓
Local server actually serves frontend/
        ↓
Developer thinks fix was tested
        ↓
Different files were running
```

## Required correction

Establish **one canonical frontend source of truth**.

The preferred direction, based on the current run script, is:

``` text
frontend/
├── index.html
├── css/
└── js/
```

### Important constraints

-   Do not accidentally delete files required by repository tooling.
-   Coordinate structural cleanup with M6 if those root files are part
    of integration/deployment assumptions.
-   Do not leave two independently edited copies that can drift.
-   Every JavaScript file referenced by the served `frontend/index.html`
    must exist in the served `frontend/js/` path.
-   Every CSS file referenced by the served `frontend/index.html` must
    exist in the served `frontend/css/` path.

If duplicate files must temporarily remain for compatibility, document
which copy is canonical and ensure they are not independently diverging.

------------------------------------------------------------------------

# 14. Script and Asset Consistency

Verify all current interactive assets referenced by the frontend
actually exist in the canonical served directory.

This includes, where currently used:

-   API client scripts.
-   Rendering scripts.
-   Application controller scripts.
-   Map scripts.
-   Galaxy button behavior.
-   Bubble cursor behavior.
-   Jelly/physics behavior.
-   CSS assets.

Do not remove these features.

The requirement is to preserve the current working visual and
interaction experience while fixing the integration underneath it.

Check browser Network and Console tabs for:

``` text
404 script
404 stylesheet
JavaScript module load failure
ReferenceError
TypeError
CORS error
Failed fetch
```

There should be no console errors during normal analysis and report
usage.

------------------------------------------------------------------------

# 15. CORS and Cross-Origin Requests

The frontend runs on a different port from the backend:

``` text
Frontend: 127.0.0.1:5500
Backend:  127.0.0.1:8000
```

Therefore requests are cross-origin.

Do not work around CORS by changing the frontend to send requests to
port 5500.

First verify whether the backend already allows the frontend origin.

If a backend CORS configuration issue exists, report it to M6 rather
than changing unrelated backend behavior yourself.

The frontend should use the correct backend URL and expose any genuine
CORS failure clearly.

------------------------------------------------------------------------

# 16. Error Handling UX

Keep the existing style and wording as much as possible.

The only required behavioral change is that genuine failures must be
visible.

Examples:

## Backend unavailable

``` text
Unable to connect to the analysis service.
```

## Backend validation error

Display the backend error in a user-friendly form.

## Unexpected response shape

Do not crash the whole page.

Show a controlled error and preserve the ability to try another
analysis.

### Do not

-   Show raw JavaScript stack traces to normal users.
-   Silently replace failed data with fixtures.
-   Permanently lock the UI after one failed request.

------------------------------------------------------------------------

# 17. Full End-to-End Acceptance Test

Before requesting review again, run the backend and frontend together.

## Terminal 1

``` powershell
uvicorn app.main:app --reload --app-dir backend
```

## Terminal 2

``` powershell
.\scripts\run_frontend.bat
```

Then test the following.

### Test A --- Backend health

Confirm:

``` text
http://127.0.0.1:8000/api/v1/health
```

returns successfully.

### Test B --- Raw email analysis

Paste a valid sample email/header.

Verify:

1.  Frontend sends request to port 8000.
2.  Route is `/api/v1/analyze`.
3.  Request uses the correct JSON payload.
4.  Response contains a real `analysis_id`.
5.  Rendered content comes from the backend, not `SAMPLE_FIXTURES`.
6.  No console errors occur.

### Test C --- Backend stopped

Stop FastAPI.

Submit an email.

Expected:

``` text
Visible connection/API error.
```

Not:

``` text
Mock analysis shown as if the real request succeeded.
```

### Test D --- Minimal/limited evidence

Use a minimal sample.

Verify the UI degrades gracefully and does not crash when optional
values are absent.

### Test E --- Geo rendering

Verify values such as:

``` text
ISP
ASN
Datacenter
Proxy
Mobile
```

render from the actual nested `origin.geo` object when available.

### Test F --- Authentication alignment

Verify the return-path alignment value renders from:

``` text
from_vs_returnpath_match
```

### Test G --- Risk signals

Verify risk signal titles render from:

``` text
label
```

### Test H --- JSON report

Use the returned `analysis_id`.

Verify:

``` text
/api/v1/report/{analysis_id}.json
```

works.

### Test I --- PDF report

Verify:

``` text
/api/v1/report/{analysis_id}.pdf
```

returns the generated PDF.

### Test J --- `.eml` upload

If upload exists in the current UI, upload a real sample `.eml`.

Verify it reaches the real backend in the correct format.

------------------------------------------------------------------------

# 18. Browser-Level Verification

Use browser Developer Tools.

## Network tab

For an analysis request, verify:

``` text
Request URL: http://127.0.0.1:8000/api/v1/analyze
Status:      successful response
Payload:     JSON containing raw_email
```

Do not accept testing based only on whether the dashboard visually
changes.

The Network tab must prove the response came from the real backend.

## Console tab

Normal analysis should not produce:

``` text
Failed to fetch
404
415
CORS errors
TypeError
ReferenceError
```

------------------------------------------------------------------------

# 19. Files Expected to Be Reviewed

At minimum, inspect:

``` text
frontend/index.html
frontend/js/api.js
frontend/js/app.js
frontend/js/render.js
frontend/js/map.js
frontend/css/styles.css
frontend/js/galaxy-buttons.js
scripts/run_frontend.bat
```

Also inspect root-level duplicate frontend files if they still exist:

``` text
index.html
js/
css/
```

Only modify files that are necessary for M5's frontend responsibility.

If an integration issue requires changing:

``` text
backend/app/main.py
backend/app/pipeline.py
backend/app/schemas.py
backend/app/core/config.py
API_CONTRACT.md
```

do not make an unrelated change. Report the issue to the responsible
module owner/M6.

------------------------------------------------------------------------

# 20. Definition of Done

M5 integration work is complete only when all of the following are true:

-   [ ] Existing frontend style and design are unchanged.
-   [ ] Existing frontend wording/text is preserved except where a
    technical correction is unavoidable.
-   [ ] Frontend points to the real backend on port 8000.
-   [ ] All routes use `/api/v1/...`.
-   [ ] Analyze request uses the correct JSON format.
-   [ ] File upload, if present, uses the backend's required upload
    format.
-   [ ] Backend failure is visible and is not silently replaced with
    mock data.
-   [ ] Mock/demo mode, if retained, is explicit and clearly separated.
-   [ ] `origin.geo.*` fields render correctly.
-   [ ] `from_vs_returnpath_match` renders correctly.
-   [ ] Risk signal `label` renders correctly.
-   [ ] Missing optional data does not crash the UI.
-   [ ] `analysis_id` is reused for JSON/PDF report retrieval.
-   [ ] JSON report endpoint works.
-   [ ] PDF report endpoint works.
-   [ ] Custody log endpoint uses `/api/v1/custody-log`.
-   [ ] Health endpoint uses `/api/v1/health`.
-   [ ] The served frontend has no missing script or CSS assets.
-   [ ] Browser Console has no normal-flow JavaScript errors.
-   [ ] Browser Network proves that analysis results come from the live
    backend.
-   [ ] Frontend and backend run together as one application.
-   [ ] No backend/API contract files were modified merely to
    accommodate frontend mistakes.
-   [ ] Duplicate frontend directories have a documented canonical
    source of truth or are cleaned up in coordination with M6.

------------------------------------------------------------------------

# Final Instruction

**Do not redesign the frontend. Do not change its style. Do not change
the existing text or branding.**

Preserve the current UI exactly as the user-facing product while
correcting the technical integration layer underneath it.

The final result must make this statement true:

> **When a user submits an email, the frontend visibly renders the real
> response produced by the actual FastAPI backend, handles missing data
> and failures gracefully, and can use the returned analysis ID to
> retrieve the corresponding JSON/PDF forensic reports without route,
> payload, schema, or asset conflicts.**
