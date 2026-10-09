"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

AUTONOMY_LEVELS = ("manual", "assisted", "autonomous")
DEFAULT_MODEL = "claude-opus-5-5"


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def load_dotenv(path: Path) -> None:
    """Read KEY=VALUE lines from a .env file without overriding real environment variables."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.removeprefix("export ").strip(), value.strip().strip("\"'")
        if key and value:
            os.environ.setdefault(key, value)


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path.cwd() / ".hub")
    host: str = "127.0.0.1"
    port: int = 8710
    model: str = DEFAULT_MODEL
    autonomy: str = "assisted"
    health_interval: float = 60.0
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    start_background_tasks: bool = True

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hub.db"

    @property
    def workspace(self) -> Path:
        return self.data_dir / "workspace"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(Path.cwd() / ".env")
        env = os.environ
        settings = cls(
            data_dir=Path(env.get("HUB_DATA_DIR") or Path.cwd() / ".hub").expanduser().resolve(),
            host=env.get("HUB_HOST", "127.0.0.1"),
            port=int(env.get("HUB_PORT", "8710")),
            model=env.get("HUB_MODEL", DEFAULT_MODEL),
            autonomy=env.get("HUB_AUTONOMY", "assisted"),
            health_interval=float(env.get("HUB_HEALTH_INTERVAL", "60")),
        )
        settings.allowed_hosts += _csv(env.get("HUB_ALLOWED_HOSTS"))
        if settings.autonomy not in AUTONOMY_LEVELS:
            raise ValueError(f"HUB_AUTONOMY must be one of {', '.join(AUTONOMY_LEVELS)}")
        return settings
