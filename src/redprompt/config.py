"""RedPrompt configuration.

Configuration is layered, with a deterministic precedence:

    explicit ``overrides`` argument  >  environment variables  >  ``.redprompt.yml``  >  defaults

Environment variables are prefixed ``REDPROMPT_`` and use ``__`` to descend into
nested sections, e.g. ``REDPROMPT_SCAN__WORKERS=8`` or ``REDPROMPT_DATABASE_URL=...``.
Values are parsed as JSON when possible (so ``8`` becomes an int and
``["prompt","api"]`` a list); otherwise they are treated as plain strings.

We use plain Pydantic models plus an explicit loader rather than the implicit
``BaseSettings`` magic on purpose: for a security tool, configuration resolution
should be obvious and unit-testable, with no hidden precedence surprises.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
)

from redprompt.exceptions import ConfigError

CONFIG_FILENAME = ".redprompt.yml"
ENV_PREFIX = "REDPROMPT_"
ENV_NESTED_DELIMITER = "__"

VALID_CATEGORIES = ("prompt", "data", "rag", "agent", "api", "file")
VALID_OUTPUT_FORMATS = ("json", "sarif", "html", "pdf")


class RetryConfig(BaseModel):
    attempts: int = Field(default=3, ge=1, le=10)
    backoff_seconds: float = Field(default=0.5, ge=0.0, le=30.0)


class SafetyConfig(BaseModel):
    """Engagement safety controls. RedPrompt is for AUTHORIZED testing only."""

    require_authorization: bool = True
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost", "::1"])
    block_public_targets: bool = True
    default_dry_run: bool = False


class TargetConfig(BaseModel):
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=120)


class ScanConfig(BaseModel):
    categories: list[str] = Field(default_factory=lambda: list(VALID_CATEGORIES[:5]))
    workers: int = Field(default=4, ge=1, le=32)
    max_requests_per_target: int = Field(default=500, ge=1, le=100_000)
    rate_limit_per_second: float = Field(default=5.0, gt=0, le=1000)
    retry: RetryConfig = Field(default_factory=RetryConfig)

    @field_validator("categories")
    @classmethod
    def _validate_categories(cls, value: list[str]) -> list[str]:
        unknown = [c for c in value if c not in VALID_CATEGORIES]
        if unknown:
            raise ValueError(
                f"unknown scan categories {unknown}; valid: {list(VALID_CATEGORIES)}"
            )
        return value


class RiskConfig(BaseModel):
    methodology: str = "default"
    minimum_confidence: float = Field(default=0.70, ge=0.0, le=1.0)
    impact_weight: bool = True
    exploitability_weight: bool = True
    confidence_weight: bool = True


class SecurityConfig(BaseModel):
    redact_secrets: bool = True
    evidence_retention_days: int = Field(default=90, ge=1, le=3650)
    store_raw_traffic: bool = False


class OutputConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "sarif", "html"])
    directory: str = "reports"

    @field_validator("formats")
    @classmethod
    def _validate_formats(cls, value: list[str]) -> list[str]:
        unknown = [f for f in value if f not in VALID_OUTPUT_FORMATS]
        if unknown:
            raise ValueError(
                f"unknown output formats {unknown}; valid: {list(VALID_OUTPUT_FORMATS)}"
            )
        return value


class LoggingConfig(BaseModel):
    # ``json`` in YAML maps to ``json_logs`` to avoid shadowing BaseModel.json().
    model_config = ConfigDict(populate_by_name=True)

    level: str = "INFO"
    json_logs: bool = Field(default=False, alias="json")

    @field_validator("level")
    @classmethod
    def _validate_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"invalid log level {value!r}; valid: {sorted(allowed)}")
        return upper


class Settings(BaseModel):
    """Fully-resolved RedPrompt settings."""

    database_url: str = "sqlite:///redprompt.db"
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    _config_path: Path | None = PrivateAttr(default=None)

    @property
    def config_path(self) -> Path | None:
        """Path of the ``.redprompt.yml`` used, or ``None`` if defaults only."""
        return self._config_path


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def find_config_file(start: Path | None = None) -> Path | None:
    """Search upward from ``start`` (default: cwd) for ``.redprompt.yml``."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def _coerce_env_value(raw: str) -> Any:
    """Parse an env var value as JSON if possible, else keep as string."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _set_nested(data: MutableMapping[str, Any], keys: list[str], value: Any) -> None:
    cursor: MutableMapping[str, Any] = data
    for key in keys[:-1]:
        existing = cursor.get(key)
        if not isinstance(existing, MutableMapping):
            existing = {}
            cursor[key] = existing
        cursor = existing
    cursor[keys[-1]] = value


def collect_env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    """Build a nested override dict from ``REDPROMPT_*`` environment variables."""
    overrides: dict[str, Any] = {}
    for name, raw in env.items():
        if not name.startswith(ENV_PREFIX):
            continue
        remainder = name[len(ENV_PREFIX) :]
        keys = [part.lower() for part in remainder.split(ENV_NESTED_DELIMITER) if part]
        if not keys:
            continue
        _set_nested(overrides, keys, _coerce_env_value(raw))
    return overrides


def _deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        if (
            key in merged
            and isinstance(merged[key], Mapping)
            and isinstance(value, Mapping)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(
    config_path: str | os.PathLike[str] | None = None,
    *,
    overrides: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    search: bool = True,
) -> Settings:
    """Load and fully resolve :class:`Settings`.

    Args:
        config_path: explicit path to a config file. If given and missing, error.
        overrides: highest-precedence dict of values (used by tests / CLI flags).
        env: environment mapping (defaults to ``os.environ``).
        search: when ``config_path`` is None, search upward for ``.redprompt.yml``.
    """
    env = os.environ if env is None else env

    file_data: dict[str, Any] = {}
    resolved_path: Path | None = None

    if config_path is not None:
        resolved_path = Path(config_path)
        if not resolved_path.is_file():
            raise ConfigError(f"config file not found: {resolved_path}")
    elif search:
        resolved_path = find_config_file()

    if resolved_path is not None:
        try:
            loaded = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {resolved_path}: {exc}") from exc
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ConfigError(f"config root of {resolved_path} must be a mapping")
        file_data = loaded

    merged = _deep_merge(file_data, collect_env_overrides(env))
    if overrides:
        merged = _deep_merge(merged, overrides)

    try:
        settings = Settings.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration: {exc}") from exc

    settings._config_path = resolved_path
    return settings
