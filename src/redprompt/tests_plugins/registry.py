"""Security-test discovery and registry.

Tests are discovered by importing the modules under ``redprompt.tests_plugins``
(and any extra packages named in config) and collecting concrete
:class:`SecurityTest` subclasses that declare a non-empty ``id``. Duplicate ids
are rejected so historic ``test_id`` references stay unambiguous.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable

from redprompt.enums import Category
from redprompt.exceptions import TestPluginError
from redprompt.tests_plugins.base import SecurityTest, TargetInfo

DEFAULT_PACKAGE = "redprompt.tests_plugins"


def _iter_subclasses(cls: type) -> Iterable[type]:
    for sub in cls.__subclasses__():
        yield sub
        yield from _iter_subclasses(sub)


def import_package_modules(package_name: str) -> None:
    """Import every submodule of a package so its test classes register."""
    try:
        package = importlib.import_module(package_name)
    except ModuleNotFoundError as exc:
        raise TestPluginError(f"test package not found: {package_name}") from exc
    if not hasattr(package, "__path__"):
        return
    for mod in pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."):
        importlib.import_module(mod.name)


class TestRegistry:
    def __init__(self) -> None:
        self._tests: dict[str, SecurityTest] = {}

    def register(self, test_cls: type[SecurityTest]) -> None:
        if inspect.isabstract(test_cls):
            return
        if not getattr(test_cls, "id", ""):
            return
        instance = test_cls()
        if instance.id in self._tests:
            existing = type(self._tests[instance.id]).__name__
            raise TestPluginError(
                f"duplicate test id {instance.id!r} ({test_cls.__name__} vs {existing})"
            )
        self._tests[instance.id] = instance

    def get(self, test_id: str) -> SecurityTest:
        try:
            return self._tests[test_id]
        except KeyError as exc:
            raise TestPluginError(f"unknown test id: {test_id}") from exc

    def all(self) -> list[SecurityTest]:
        return sorted(self._tests.values(), key=lambda t: t.id)

    def by_category(self, category: Category | str) -> list[SecurityTest]:
        cat = Category(category) if not isinstance(category, Category) else category
        return [t for t in self.all() if t.category is cat]

    def for_target(
        self,
        target: TargetInfo,
        *,
        categories: list[str] | None = None,
        test_ids: list[str] | None = None,
    ) -> list[SecurityTest]:
        """Select applicable tests, filtered by category and/or explicit ids."""
        selected = self.all()
        if test_ids:
            wanted = set(test_ids)
            selected = [t for t in selected if t.id in wanted]
        if categories:
            cats = {Category(c) for c in categories}
            selected = [t for t in selected if t.category in cats]
        return [t for t in selected if t.applies_to(target)]

    def __len__(self) -> int:
        return len(self._tests)


def build_registry(packages: Iterable[str] = (DEFAULT_PACKAGE,)) -> TestRegistry:
    """Discover tests from the given packages and return a populated registry.

    Only classes defined *within* the given packages are registered — this keeps
    discovery deterministic and prevents unrelated SecurityTest subclasses (e.g.
    fakes defined in a test suite) from leaking into the registry.
    """
    prefixes = tuple(packages)
    for package in prefixes:
        import_package_modules(package)
    registry = TestRegistry()
    for cls in _iter_subclasses(SecurityTest):
        module = getattr(cls, "__module__", "")
        if module.startswith(prefixes):
            registry.register(cls)
    return registry
