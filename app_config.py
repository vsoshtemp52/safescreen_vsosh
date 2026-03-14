import json
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = {
    "tesseract_cmd": r"C:\\Program Files\\Tesseract-OCR\\tesseract.exe",
    "shield_padding": 30,
    "memory_duration": 60.0,
    "recheck_interval": 55.0,
    "max_windows_to_check": 10,
    "scanner_sleep": 0.05,
    "protection_level": 3,
    "whitelist_words": [],
    "blacklist_words": [],
}


def get_default_config() -> dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG)


def get_default_config_path() -> Path:
    return Path(__file__).resolve().with_name("settings.json")


def _normalize_word_list(value: Any) -> list[str]:
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        return []

    out = []
    seen = set()
    for item in raw_items:
        text = str(item).strip().lower()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _coerce_config(config: dict[str, Any]) -> dict[str, Any]:
    merged = get_default_config()
    merged.update(config or {})

    merged["tesseract_cmd"] = str(merged.get("tesseract_cmd", DEFAULT_CONFIG["tesseract_cmd"]))

    merged["shield_padding"] = max(0, int(merged.get("shield_padding", DEFAULT_CONFIG["shield_padding"])))
    merged["memory_duration"] = max(1.0, float(merged.get("memory_duration", DEFAULT_CONFIG["memory_duration"])))
    merged["recheck_interval"] = max(1.0, float(merged.get("recheck_interval", DEFAULT_CONFIG["recheck_interval"])))
    merged["max_windows_to_check"] = max(1, int(merged.get("max_windows_to_check", DEFAULT_CONFIG["max_windows_to_check"])))
    merged["scanner_sleep"] = max(0.01, float(merged.get("scanner_sleep", DEFAULT_CONFIG["scanner_sleep"])))

    level = int(merged.get("protection_level", DEFAULT_CONFIG["protection_level"]))
    merged["protection_level"] = min(5, max(1, level))

    merged["whitelist_words"] = _normalize_word_list(merged.get("whitelist_words", []))
    merged["blacklist_words"] = _normalize_word_list(merged.get("blacklist_words", []))

    return merged


def load_config(path: Path | None = None) -> dict[str, Any]:
    target_path = path or get_default_config_path()
    if not target_path.exists():
        return get_default_config()

    try:
        with target_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return get_default_config()
        return _coerce_config(data)
    except Exception:
        return get_default_config()


def save_config(config: dict[str, Any], path: Path | None = None) -> Path:
    target_path = path or get_default_config_path()
    normalized = _coerce_config(config)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with target_path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, ensure_ascii=False, indent=2)
        f.write("\n")

    return target_path
