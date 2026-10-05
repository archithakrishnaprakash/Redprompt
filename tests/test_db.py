"""Tests for the database schema, relationships, and constraints."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from redprompt.core.context import AppContext
from redprompt.db.models import (
    AttackSurfaceNode,
    Evidence,
    Finding,
    Scan,
    Target,
    TestExecution,
    Tool,
)
from redprompt.enums import (
    AppType,
    Category,
    DetectionSource,
    Severity,
    SurfaceStatus,
    TestStatus,
)


def _make_target(name: str = "lab-agent") -> Target:
    return Target(
        name=name,
        base_url="http://127.0.0.1:8000",
        app_type=AppType.AGENT,
        agent_enabled=True,
        authorized=True,
        tags=["lab"],
    )


def test_create_and_read_target(ctx: AppContext) -> None:
    with ctx.session() as s:
        s.add(_make_target())
    with ctx.session() as s:
        target = s.query(Target).filter_by(name="lab-agent").one()
        assert target.app_type is AppType.AGENT
        assert target.authorized is True
        assert target.tags == ["lab"]
        assert target.created_at is not None


def test_unique_target_name(ctx: AppContext) -> None:
    with ctx.session() as s:
        s.add(_make_target("dup"))
    with pytest.raises(IntegrityError):
        with ctx.session() as s:
            s.add(_make_target("dup"))


def test_cascade_delete_scans_and_tools(ctx: AppContext) -> None:
    with ctx.session() as s:
        target = _make_target("cascade")
        target.tools.append(Tool(name="lookup", source=DetectionSource.USER_PROVIDED))
        target.scans.append(
            Scan(scan_uuid=str(uuid.uuid4()), categories=["agent"])
        )
        s.add(target)

    with ctx.session() as s:
        target = s.query(Target).filter_by(name="cascade").one()
        s.delete(target)

    with ctx.session() as s:
        assert s.query(Tool).count() == 0
        assert s.query(Scan).count() == 0


def test_execution_confidence_check_constraint(ctx: AppContext) -> None:
    with ctx.session() as s:
        s.add(_make_target("cc"))
    with ctx.session() as s:
        target = s.query(Target).filter_by(name="cc").one()
        scan = Scan(scan_uuid=str(uuid.uuid4()), target_id=target.id, categories=["prompt"])
        s.add(scan)
        s.flush()
        s.add(
            TestExecution(
                scan_id=scan.id,
                test_id="RP-PI-001",
                status=TestStatus.FAIL,
                confidence=1.5,  # out of range -> CHECK violation
            )
        )
        with pytest.raises(IntegrityError):
            s.flush()


def test_finding_with_evidence_relationship(ctx: AppContext) -> None:
    with ctx.session() as s:
        target = _make_target("ev")
        s.add(target)
        s.flush()
        scan = Scan(scan_uuid=str(uuid.uuid4()), target_id=target.id, categories=["prompt"])
        s.add(scan)
        s.flush()
        finding = Finding(
            finding_id="RP-PI-0001",
            scan_id=scan.id,
            target_id=target.id,
            test_id="RP-PI-001",
            title="Test finding",
            category=Category.PROMPT,
            severity=Severity.HIGH,
            confidence=0.9,
        )
        finding.evidence.append(
            Evidence(test_id="RP-PI-001", content_hash="deadbeef", snippets=["x"])
        )
        s.add(finding)

    with ctx.session() as s:
        finding = s.query(Finding).filter_by(finding_id="RP-PI-0001").one()
        assert finding.severity is Severity.HIGH
        assert len(finding.evidence) == 1
        assert finding.evidence[0].content_hash == "deadbeef"


def test_attack_surface_self_reference(ctx: AppContext) -> None:
    with ctx.session() as s:
        target = _make_target("surface")
        s.add(target)
        s.flush()
        root = AttackSurfaceNode(
            target_id=target.id,
            component="agent",
            label="AI Agent",
            status=SurfaceStatus.DISCOVERED,
            detection=DetectionSource.CONFIGURED,
        )
        s.add(root)
        s.flush()
        child = AttackSurfaceNode(
            target_id=target.id,
            parent_id=root.id,
            component="tool",
            label="lookup",
            status=SurfaceStatus.UNTESTED,
        )
        s.add(child)

    with ctx.session() as s:
        nodes = s.query(AttackSurfaceNode).all()
        assert len(nodes) == 2
        parents = [n for n in nodes if n.parent_id is None]
        assert parents[0].detection is DetectionSource.CONFIGURED
