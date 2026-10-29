"""Settings loaded from the environment, with a minimal .env reader."""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent


def _home() -> Path:
    """Where keys (.env), history and caches live.

    PARADOX_HOME wins. A source checkout keeps everything in the checkout, as
    before; an installed copy (pipx/pip) uses ~/.paradox-detector.
    """
    if os.environ.get("PARADOX_HOME"):
        return Path(os.environ["PARADOX_HOME"]).expanduser()
    if (ROOT / "pyproject.toml").exists():
        return ROOT
    return Path.home() / ".paradox-detector"


HOME = _home()
DATA_DIR = HOME / "data"
CACHE_DIR = HOME / ".cache"
ENV_FILE = HOME / ".env"


def load_dotenv(path: Path = ENV_FILE) -> None:
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
