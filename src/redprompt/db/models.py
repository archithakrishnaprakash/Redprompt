"""RedPrompt relational models.

The schema captures the full assessment lifecycle:

    Target ─┬─ Tool
            ├─ AttackSurfaceNode
            └─ Scan ─┬─ TestExecution ─┬─ Evidence
                     └─ Finding ───────┴─ Retest

``TestCase`` is a persisted snapshot of a registered test plugin (so historic
scans remain interpretable even if a plugin changes). ``Report`` and
``ConfigRecord`` round out reporting and persisted settings.

Enums are stored as VARCHAR with a CHECK constraint (``native_enum=False``) so the
schema is identical on SQLite and PostgreSQL and remains self-documenting.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from redprompt.db.base import Base, TimestampMixin
from redprompt.enums import (
    AppType,
    AuthMethod,
    Category,
    DetectionSource,
    Exploitability,
    FindingStatus,
    RetestStatus,
    ScanStatus,
    Severity,
    SurfaceStatus,
    TestStatus,
)


def _enum(enum_cls: type, name: str) -> Enum:
    """String-backed enum column (portable across SQLite/PostgreSQL)."""
    return Enum(enum_cls, native_enum=False, length=32, name=name, validate_strings=True)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    base_url: Mapped[str] = mapped_column(String(512))
    api_endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)

    app_type: Mapped[AppType] = mapped_column(_enum(AppType, "app_type"), default=AppType.LLM)
    auth_method: Mapped[AuthMethod] = mapped_column(
        _enum(AuthMethod, "auth_method"), default=AuthMethod.NONE
    )
    llm_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)

    rag_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    file_upload: Mapped[bool] = mapped_column(Boolean, default=False)
    streaming: Mapped[bool] = mapped_column(Boolean, default=False)

    environment: Mapped[str] = mapped_column(String(32), default="local")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Safety: a target must be explicitly authorized before it can be scanned.
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)

    # Flexible provider/auth metadata (auth header name, model name, ...). Secrets
    # are NOT stored here; credentials are resolved from the environment at runtime.
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scans: Mapped[list[Scan]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    tools: Mapped[list[Tool]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    surface: Mapped[list[AttackSurfaceNode]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="target")


class Tool(Base, TimestampMixin):
    """An agent tool exposed by the target (inventory for agent-security tests)."""

    __tablename__ = "tools"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[DetectionSource] = mapped_column(
        _enum(DetectionSource, "tool_source"), default=DetectionSource.USER_PROVIDED
    )

    target: Mapped[Target] = relationship(back_populates="tools")

    __table_args__ = (UniqueConstraint("target_id", "name", name="tool_name_per_target"),)


class AttackSurfaceNode(Base, TimestampMixin):
    """A node in the target's attack-surface graph."""

    __tablename__ = "attack_surface"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("attack_surface.id", ondelete="CASCADE"), nullable=True
    )
    component: Mapped[str] = mapped_column(String(64))  # prompt, llm_api, rag, tool, file, auth
    label: Mapped[str] = mapped_column(String(128))
    status: Mapped[SurfaceStatus] = mapped_column(
        _enum(SurfaceStatus, "surface_status"), default=SurfaceStatus.DISCOVERED
    )
    detection: Mapped[DetectionSource] = mapped_column(
        _enum(DetectionSource, "surface_detection"), default=DetectionSource.UNKNOWN
    )

    target: Mapped[Target] = relationship(back_populates="surface")
    children: Mapped[list[AttackSurfaceNode]] = relationship(
        cascade="all, delete-orphan"
    )


class TestCase(Base, TimestampMixin):
    """Persisted snapshot of a registered security-test plugin."""

    __tablename__ = "test_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # RP-PI-001
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[Category] = mapped_column(_enum(Category, "testcase_category"))
    description: Mapped[str] = mapped_column(Text, default="")
    default_severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "testcase_severity"), default=Severity.MEDIUM
    )
    version: Mapped[str] = mapped_column(String(16), default="0.1.0")
    experimental: Mapped[bool] = mapped_column(Boolean, default=False)
    heuristic: Mapped[bool] = mapped_column(Boolean, default=True)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))

    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.PENDING
    )
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    inconclusive: Mapped[int] = mapped_column(Integer, default=0)
    errored: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)

    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    target: Mapped[Target] = relationship(back_populates="scans")
    executions: Mapped[list[TestExecution]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class TestExecution(Base, TimestampMixin):
    __tablename__ = "test_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    test_id: Mapped[str] = mapped_column(String(32), index=True)

    status: Mapped[TestStatus] = mapped_column(_enum(TestStatus, "execution_status"))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(Text, default="")
    indicators: Mapped[list[Any]] = mapped_column(JSON, default=list)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="executions")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="execution", cascade="all, delete-orphan"
    )
    finding: Mapped[Finding | None] = relationship(back_populates="execution")

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence_range"),
    )


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # RP-PI-0042
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_executions.id", ondelete="SET NULL"), nullable=True
    )
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    test_id: Mapped[str] = mapped_column(String(32), index=True)

    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[Category] = mapped_column(_enum(Category, "finding_category"))
    description: Mapped[str] = mapped_column(Text, default="")
    affected_component: Mapped[str | None] = mapped_column(String(128), nullable=True)

    impact: Mapped[str] = mapped_column(Text, default="")
    exploitability: Mapped[Exploitability] = mapped_column(
        _enum(Exploitability, "finding_exploitability"), default=Exploitability.MEDIUM
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "finding_severity"))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    reproduction_steps: Mapped[list[str]] = mapped_column(JSON, default=list)

    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN
    )
    retest_status: Mapped[RetestStatus] = mapped_column(
        _enum(RetestStatus, "finding_retest_status"), default=RetestStatus.PENDING
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    target: Mapped[Target] = relationship(back_populates="findings")
    execution: Mapped[TestExecution | None] = relationship(back_populates="finding")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")
    retests: Mapped[list[Retest]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence_range"),
        CheckConstraint("risk_score >= 0.0 AND risk_score <= 10.0", name="risk_range"),
    )


class Evidence(Base, TimestampMixin):
    """Immutable evidence record tying a finding back to a test execution.

    All free-text/JSON fields are redacted before persistence (see the evidence
    subsystem). ``content_hash`` provides tamper-evidence for the stored record.
    """

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True
    )
    test_id: Mapped[str] = mapped_column(String(32), index=True)

    request: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prompt_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_invocation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    detection_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    snippets: Mapped[list[str]] = mapped_column(JSON, default=list)

    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str] = mapped_column(String(32), default="local")
    target_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    execution: Mapped[TestExecution | None] = relationship(back_populates="evidence")
    finding: Mapped[Finding | None] = relationship(back_populates="evidence")


class Retest(Base, TimestampMixin):
    __tablename__ = "retests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    retest_number: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[TestStatus] = mapped_column(_enum(TestStatus, "retest_status_result"))
    previous_evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    new_evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[str] = mapped_column(Text, default="")

    finding: Mapped[Finding] = relationship(back_populates="retests")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    formats: Mapped[list[str]] = mapped_column(JSON, default=list)
    path: Mapped[str] = mapped_column(String(512), default="")
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ConfigRecord(Base, TimestampMixin):
    """Persisted key/value configuration snapshots (audit + reproducibility)."""

    __tablename__ = "configuration"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
