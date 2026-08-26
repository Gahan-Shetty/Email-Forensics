"""API-level tests.  OWNER: M6 - only you edit this file.

Needs fastapi + httpx installed (they are in requirements.txt).
"""
from __future__ import annotations

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402

from backend.app.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "module_status" in r.json()


def test_mock_endpoint_matches_contract():
    r = client.get("/api/v1/mock/analyze")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "1.0"
    assert body["origin"]["confidence"] in {"high", "medium", "low"}
    assert len(body["risk"]["signals"]) == 5


def test_analyze_paste(sample_phish):
    r = client.post("/api/v1/analyze",
                    json={"raw_email": sample_phish, "options": {"skip_geoip": True}})
    assert r.status_code == 200
    assert r.json()["input"]["source"] == "paste"


def test_analyze_file_upload(sample_phish):
    r = client.post("/api/v1/analyze",
                    files={"file": ("sample.eml", sample_phish.encode(), "message/rfc822")})
    assert r.status_code == 200
    assert r.json()["input"]["source"] == "file"


def test_empty_input_returns_structured_error():
    r = client.post("/api/v1/analyze", json={"raw_email": "   "})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "EMPTY_INPUT"


def test_garbage_input_returns_unparseable():
    r = client.post("/api/v1/analyze", json={"raw_email": "just some text with no headers"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "UNPARSEABLE_EMAIL"


def test_unsupported_extension_rejected():
    r = client.post("/api/v1/analyze",
                    files={"file": ("evil.exe", b"MZ...", "application/octet-stream")})
    assert r.status_code == 415


def test_unknown_report_id_404s():
    r = client.get("/api/v1/report/does-not-exist.json")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "REPORT_NOT_FOUND"


def test_custody_log_endpoint():
    r = client.get("/api/v1/custody-log")
    assert r.status_code == 200
    assert "entries" in r.json() and "verification" in r.json()
