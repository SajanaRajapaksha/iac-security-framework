#!/usr/bin/env python3
import json
import hashlib
from pathlib import Path

RISK_BANDS = [
    "VERY_LOW_RISK",
    "LOW_RISK",
    "MODERATE_RISK",
    "HIGH_RISK",
    "CRITICAL_RISK"
]

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5
}

def safe_read_json(path: str) -> dict:
    try:
        p = Path(path)
        if not p.is_file():
            return None
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def safe_write_json(path: str, data: dict):
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error writing {path}: {e}")

def get_risk_band_index(band: str) -> int:
    try:
        return RISK_BANDS.index(band)
    except ValueError:
        return 99

def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "UNKNOWN").upper(), 99))
