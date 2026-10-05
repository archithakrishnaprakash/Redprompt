"""FastAPI application factory for the RedPrompt REST API + dashboard.

Requires the optional ``api`` extra (FastAPI + uvicorn). OpenAPI docs are served
automatically at ``/docs`` and ``/openapi.json``. Dashboard is at ``/``.

Authentication: if a bearer token is configured (``--token`` /
``REDPROMPT_DASHBOARD_TOKEN``), every ``/api/*`` route requires
``Authorization: Bearer <token>``. With no token the API is open (intended for
local use only) and the dashboard shows a warning.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse

from redprompt.api.attack_surface import build_attack_surface
from redprompt.api.dashboard import DASHBOARD_HTML
from redprompt.api.schemas import RetestOut, ScanRequest
from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator
from redprompt.db.models import Finding, Scan, Target
from redprompt.exceptions import RedPromptError, SafetyViolation
from redprompt.findings import FindingService
from redprompt.reporting.builder import ReportBuilder
from redprompt.retest import RetestEngine
from redprompt.targets.schemas import TargetCreate, TargetView
from redprompt.targets.service import TargetService
from redprompt.tests_plugins.registry import build_registry
from redprompt.version import get_version


def create_app(ctx: AppContext, *, token: str | None = None) -> FastAPI:
    app = FastAPI(
        title="RedPrompt API",
        version=get_version(),
        description="AI Application Security Testing & Red Teaming Platform — REST API.",
    )
    registry = build_registry()

    def require_auth(request: Request) -> None:
        if not token:
            return
        header = request.headers.get("authorization", "")
        if header != f"Bearer {token}":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid bearer token")

    auth = [Depends(require_auth)]

    # ---- dashboard + meta --------------------------------------------------
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        return DASHBOARD_HTML

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        with ctx.session() as s:
            return {
                "status": "ok",
                "version": get_version(),
                "targets": s.query(Target).count(),
                "scans": s.query(Scan).count(),
                "findings": s.query(Finding).count(),
                "tests": len(registry),
                "auth_required": bool(token),
            }

    # ---- targets -----------------------------------------------------------
    @app.get("/api/targets", dependencies=auth)
    def list_targets() -> list[dict[str, Any]]:
        with ctx.session() as s:
            return [TargetView.model_validate(t).model_dump() for t in TargetService(s).list()]

    @app.post("/api/targets", dependencies=auth, status_code=201)
    def create_target(body: TargetCreate) -> dict[str, Any]:
        try:
            with ctx.session() as s:
                t = TargetService(s).add(body)
                return TargetView.model_validate(t).model_dump()
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @app.get("/api/targets/{identifier}", dependencies=auth)
    def get_target(identifier: str) -> dict[str, Any]:
        try:
            with ctx.session() as s:
                return TargetView.model_validate(TargetService(s).get(identifier)).model_dump()
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    @app.get("/api/targets/{identifier}/attack-surface", dependencies=auth)
    def attack_surface(identifier: str) -> dict[str, Any]:
        with ctx.session() as s:
            try:
                target = TargetService(s).get(identifier)
            except RedPromptError as exc:
                raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
            findings = s.query(Finding).filter_by(target_id=target.id).all()
            scans = s.query(Scan).filter_by(target_id=target.id).all()
            tested = {c for scan in scans for c in (scan.categories or [])}
            vulnerable = {f.category.value for f in findings}
            return build_attack_surface(
                app_type=target.app_type.value,
                rag_enabled=target.rag_enabled,
                agent_enabled=target.agent_enabled,
                file_upload=target.file_upload,
                auth_method=target.auth_method.value,
                tools=[t.name for t in target.tools],
                tested_categories=tested,
                vulnerable_categories=vulnerable,
            )

    # ---- scans -------------------------------------------------------------
    @app.post("/api/scans", dependencies=auth)
    async def run_scan(body: ScanRequest) -> dict[str, Any]:
        orch = Orchestrator(ctx, registry)
        try:
            summary = await orch.run_scan(
                body.target, categories=body.categories, test_ids=body.test_ids,
                dry_run=body.dry_run, workers=body.workers,
            )
        except SafetyViolation as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        return {
            "scan_uuid": summary.scan_uuid,
            "target": summary.target_name,
            "status": summary.status,
            "counts": summary.counts,
            "findings": [f.__dict__ for f in summary.findings],
        }

    @app.get("/api/scans", dependencies=auth)
    def list_scans() -> list[dict[str, Any]]:
        with ctx.session() as s:
            scans = s.query(Scan).order_by(Scan.created_at.desc()).all()
            return [
                {
                    "scan_uuid": sc.scan_uuid, "status": sc.status.value,
                    "total_tests": sc.total_tests, "failed": sc.failed,
                    "created_at": sc.created_at.isoformat(),
                }
                for sc in scans
            ]

    @app.get("/api/scans/{scan_uuid}", dependencies=auth)
    def get_scan(scan_uuid: str) -> dict[str, Any]:
        with ctx.session() as s:
            sc = s.query(Scan).filter_by(scan_uuid=scan_uuid).one_or_none()
            if sc is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no such scan")
            return {
                "scan_uuid": sc.scan_uuid, "status": sc.status.value,
                "categories": sc.categories, "total_tests": sc.total_tests,
                "passed": sc.passed, "failed": sc.failed,
                "inconclusive": sc.inconclusive, "errored": sc.errored, "skipped": sc.skipped,
            }

    # ---- findings ----------------------------------------------------------
    @app.get("/api/findings", dependencies=auth)
    def list_findings(severity: str | None = None, status_: str | None = None) -> list[dict[str, Any]]:
        with ctx.session() as s:
            rows = FindingService(s).list(severity=severity, status=status_)
            return [
                {
                    "finding_id": f.finding_id, "title": f.title, "category": f.category.value,
                    "severity": f.severity.value, "risk_score": f.risk_score,
                    "confidence": f.confidence, "status": f.status.value, "test_id": f.test_id,
                }
                for f in rows
            ]

    @app.get("/api/findings/{finding_id}", dependencies=auth)
    def get_finding(finding_id: str) -> dict[str, Any]:
        try:
            with ctx.session() as s:
                f = FindingService(s).get(finding_id)
                return {
                    "finding_id": f.finding_id, "title": f.title, "category": f.category.value,
                    "severity": f.severity.value, "risk_score": f.risk_score,
                    "confidence": f.confidence, "status": f.status.value,
                    "description": f.description, "impact": f.impact, "remediation": f.remediation,
                    "references": f.references, "reproduction_steps": f.reproduction_steps,
                    "risk_factors": f.risk_factors,
                }
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    @app.post("/api/findings/{finding_id}/retest", dependencies=auth, response_model=RetestOut)
    async def retest_finding(finding_id: str) -> RetestOut:
        try:
            outcome = await RetestEngine(ctx, registry).retest(finding_id)
        except SafetyViolation as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        return RetestOut(
            finding_id=outcome.finding_id, previous_status=outcome.previous_status,
            new_status=outcome.new_status, result_status=outcome.result_status,
            retest_number=outcome.retest_number, explanation=outcome.explanation,
        )

    # ---- tests + reports ---------------------------------------------------
    @app.get("/api/tests", dependencies=auth)
    def list_tests() -> list[dict[str, Any]]:
        return [t.as_metadata() for t in registry.all()]

    @app.get("/api/reports/{scan_uuid}", dependencies=auth)
    def get_report(scan_uuid: str) -> JSONResponse:
        try:
            with ctx.session() as s:
                data = ReportBuilder(s).for_scan(scan_uuid)
                return JSONResponse(data.to_dict())
        except RedPromptError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    return app
