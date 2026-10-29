"""Settings loaded from the environment, with a minimal .env reader."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / ".cache"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if value[:1] in ("'", '"') and value[0] in value[1:]:
            value = value[1:value.index(value[0], 1)]       # quoted: keep as-is
        else:
            value = value.split(" #", 1)[0].split("\t#", 1)[0].strip()  # drop inline comment
            if value.startswith("#"):
                value = ""
        os.environ.setdefault(key.strip(), value)


load_dotenv()


def key(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


HTTP_TIMEOUT = float(os.environ.get("PARADOX_HTTP_TIMEOUT", "12"))
SCAN_CACHE_SECONDS = int(os.environ.get("PARADOX_SCAN_CACHE_SECONDS", "600"))
CLAUDE_MODEL = os.environ.get("PARADOX_CLAUDE_MODEL", "claude-opus-5-5")
