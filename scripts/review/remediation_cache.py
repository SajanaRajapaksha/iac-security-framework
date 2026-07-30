#!/usr/bin/env python3
import hashlib
from pathlib import Path
from scripts.review.review_utils import safe_read_json, safe_write_json

CACHE_PATH = Path("cache/review/remediation-guidance.json")

def _normalize_str(s: str) -> str:
    return str(s).strip().lower() if s else ""

def generate_cache_key(prompt_version: str, stage: str, scanner: str, check_id: str, resource_type: str, title: str, description: str) -> str:
    parts = [
        _normalize_str(prompt_version),
        _normalize_str(stage),
        _normalize_str(scanner),
        _normalize_str(check_id),
        _normalize_str(resource_type),
        _normalize_str(title),
        _normalize_str(description)
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def load_cache() -> dict:
    # Ensure ROOT_DIR resolves properly if called from other modules
    # cache should be at repository root
    root = Path(__file__).resolve().parent.parent.parent
    path = root / CACHE_PATH
    return safe_read_json(str(path)) or {}

def save_cache(cache_data: dict):
    root = Path(__file__).resolve().parent.parent.parent
    path = root / CACHE_PATH
    safe_write_json(str(path), cache_data)
