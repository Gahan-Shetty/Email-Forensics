"""Shared fixtures.  OWNER: M6.  Add your own fixtures in YOUR test file."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def fixture_response() -> dict:
    return json.loads((ROOT / "fixtures" / "sample_response.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def samples() -> dict[str, str]:
    """{'01_high_confidence_direct': '<raw text>', ...}"""
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(SAMPLES.glob("*.eml"))}


@pytest.fixture
def sample_phish(samples) -> str:
    return samples["02_spoofed_paypal_hosted"]
