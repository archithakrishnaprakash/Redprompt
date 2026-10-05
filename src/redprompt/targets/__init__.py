"""Target management: schemas, service (CRUD), and connection mapping."""

from __future__ import annotations

from redprompt.targets.schemas import (
    TargetCreate,
    TargetView,
    connection_from_target,
)

__all__ = ["TargetCreate", "TargetView", "connection_from_target"]
