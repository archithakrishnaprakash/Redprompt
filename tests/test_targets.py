"""Tests for the target service (SQLAlchemy-backed)."""

from __future__ import annotations

import pytest

from redprompt.core.context import AppContext
from redprompt.enums import AppType, AuthMethod
from redprompt.exceptions import TargetError
from redprompt.targets.schemas import TargetCreate
from redprompt.targets.service import TargetService, make_client, provider_for_target


def _create(**kw) -> TargetCreate:
    base = dict(name="lab", base_url="http://127.0.0.1:8000", provider="generic")
    base.update(kw)
    return TargetCreate(**base)


def test_add_and_get(ctx: AppContext) -> None:
    with ctx.session() as s:
        svc = TargetService(s)
        target = svc.add(_create(model="m", auth_env="K"))
        assert target.id is not None
        assert target.extra["model"] == "m"
    with ctx.session() as s:
        got = TargetService(s).get("lab")
        assert got.base_url == "http://127.0.0.1:8000"


def test_duplicate_name_rejected(ctx: AppContext) -> None:
    with ctx.session() as s:
        TargetService(s).add(_create())
    with pytest.raises(TargetError):
        with ctx.session() as s:
            TargetService(s).add(_create())


def test_get_missing_raises(ctx: AppContext) -> None:
    with pytest.raises(TargetError):
        with ctx.session() as s:
            TargetService(s).get("nope")


def test_list_and_remove(ctx: AppContext) -> None:
    with ctx.session() as s:
        svc = TargetService(s)
        svc.add(_create(name="a"))
        svc.add(_create(name="b"))
    with ctx.session() as s:
        assert {t.name for t in TargetService(s).list()} == {"a", "b"}
    with ctx.session() as s:
        TargetService(s).remove("a")
    with ctx.session() as s:
        assert {t.name for t in TargetService(s).list()} == {"b"}


def test_authorize_toggle(ctx: AppContext) -> None:
    with ctx.session() as s:
        TargetService(s).add(_create(authorized=False))
    with ctx.session() as s:
        t = TargetService(s).set_authorized("lab", True)
        assert t.authorized is True
    with ctx.session() as s:
        t = TargetService(s).set_authorized("lab", False)
        assert t.authorized is False


def test_get_by_id(ctx: AppContext) -> None:
    with ctx.session() as s:
        target = TargetService(s).add(_create())
        tid = target.id
    with ctx.session() as s:
        assert TargetService(s).get(tid).name == "lab"


def test_provider_for_target(ctx: AppContext) -> None:
    with ctx.session() as s:
        target = TargetService(s).add(
            _create(provider="openai", model="gpt", auth_method=AuthMethod.BEARER, auth_env="OPENAI_API_KEY")
        )
        client = make_client(ctx.settings)
        provider = provider_for_target(target, client, env={"OPENAI_API_KEY": "sk-x"})
        assert provider.name == "openai"
        assert provider._credential == "sk-x"
        assert provider.metadata()["model"] == "gpt"


def test_app_type_persisted(ctx: AppContext) -> None:
    with ctx.session() as s:
        t = TargetService(s).add(_create(app_type=AppType.AGENT, agent_enabled=True))
        assert t.app_type is AppType.AGENT
        assert t.agent_enabled is True
