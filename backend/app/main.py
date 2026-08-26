"""FastAPI app + routes.   OWNER: M6 (Integration).

The only file that imports fastapi/pydantic.  Every member module is plain
stdlib Python returning plain dicts, which means members can unit-test their
work with `python -c` and no dependencies installed.

Run:  uvicorn backend.app.main:app --reload --port 8000
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Body, FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .core import config
from .pipeline import run_analysis
from .report import custody_log as m4_custody
from .report import pdf_renderer as m4_pdf
from .report import report_builder as m4_report
from .schemas import AnalysisResponse, AnalyzeRequest, ErrorBody, ErrorResponse

app = FastAPI(
    title="SIH26106 Email Forensic Analyzer",
    version="1.0",
    description="Header forensics, confidence-scored origin analysis, and "
                "tamper-evident forensic reporting for suspicious email.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOW_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store: analysis_id -> full analysis dict.  No DB for the MVP by
# design (see the tech-stack table).  Restarting the server clears it, which is
# fine - the evidence/ folder and custody log persist.
_STORE: dict[str, dict] = {}


def _error(status: int, code: str, message: str, detail=None) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, detail=detail))
    return JSONResponse(status_code=status, content=body.model_dump())


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    """Never leak a stack trace to the client."""
    return _error(500, "INTERNAL", "An internal error occurred while analysing this message.")


@app.get("/api/v1/health")
def health() -> dict:
    """Liveness + which modules are real vs still stubbed."""
    probe = run_analysis("From: probe@example.com\r\nSubject: probe\r\n\r\nprobe",
                         skip_geoip=True)
    return {
        "status": "ok",
        "schema_version": config.SCHEMA_VERSION,
        "module_status": probe["module_status"],
        "geoip_provider": config.GEOIP_PROVIDER,
        "demo_mode": config.DEMO_MODE,
    }


@app.get("/api/v1/mock/analyze", response_model=AnalysisResponse)
def mock_analyze():
    """The frozen fixture. Frontend builds against this from minute one.

    This endpoint is why nobody on this team is ever blocked. It works before
    any backend logic exists and its shape is identical to /analyze.
    """
    if not config.FIXTURE_PATH.exists():
        return _error(500, "INTERNAL", "fixtures/sample_response.json is missing.")
    return json.loads(config.FIXTURE_PATH.read_text(encoding="utf-8"))


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze(
    payload: AnalyzeRequest | None = Body(default=None),
    file: UploadFile | None = File(default=None),
):
    """Main pipeline. Accepts JSON {raw_email, options} OR multipart file=<.eml>."""
    if config.DEMO_MODE:
        return mock_analyze()

    raw, source, filename = "", "paste", None

    if file is not None:
        ext = Path(file.filename or "").suffix.lower()
        if ext and ext not in config.ALLOWED_EXTENSIONS:
            return _error(415, "UNSUPPORTED_FILE_TYPE",
                          f"Only {', '.join(sorted(config.ALLOWED_EXTENSIONS))} files are accepted.")
        data = await file.read()
        if len(data) > config.MAX_UPLOAD_BYTES:
            return _error(413, "FILE_TOO_LARGE",
                          f"File exceeds the {config.MAX_UPLOAD_BYTES // 1000} KB limit.")
        raw, source, filename = data.decode("utf-8", errors="replace"), "file", file.filename
    elif payload is not None:
        raw = payload.raw_email or ""

    if not raw.strip():
        return _error(400, "EMPTY_INPUT",
                      "Paste the raw email source or upload a .eml file to analyse.")
    if ":" not in raw.split("\n", 1)[0]:
        return _error(400, "UNPARSEABLE_EMAIL",
                      "No email headers were found. Paste the full raw source, "
                      "including the Received and From headers.")

    opts = payload.options if payload else None
    result = run_analysis(
        raw, source=source, filename=filename,
        skip_geoip=bool(opts and opts.skip_geoip),
        include_body_heuristics=bool(opts.include_body_heuristics) if opts else True,
    )
    _STORE[result["analysis_id"]] = result
    return result


@app.get("/api/v1/report/{analysis_id}.json")
def report_json(analysis_id: str):
    analysis = _STORE.get(analysis_id)
    if not analysis:
        return _error(404, "REPORT_NOT_FOUND", "No analysis found for that id.")
    return m4_report.build_report_payload(analysis)


@app.get("/api/v1/report/{analysis_id}.pdf")
def report_pdf(analysis_id: str):
    analysis = _STORE.get(analysis_id)
    if not analysis:
        return _error(404, "REPORT_NOT_FOUND", "No analysis found for that id.")
    out = config.REPORT_OUTPUT_DIR / f"{analysis_id}.pdf"
    try:
        m4_pdf.render_pdf(m4_report.build_report_payload(analysis), str(out))
    except NotImplementedError:
        return _error(501, "INTERNAL",
                      "PDF export is not implemented yet. Use the JSON report.")
    return FileResponse(str(out), media_type="application/pdf",
                        filename=f"forensic-report-{analysis_id[:8]}.pdf")


@app.get("/api/v1/custody-log")
def custody_log():
    return {"entries": m4_custody.read_custody_log(),
            "verification": m4_custody.verify_custody_chain()}
