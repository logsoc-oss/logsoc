"""LOGSOC Plugin System

Plugins are Python packages discovered from the ``plugins/`` directory
at the project root *or* from entry-point group ``logsoc.plugins``.

Each plugin package **must** expose a ``Plugin`` subclass::

    from logsoc.plugins import Plugin, PluginContext

    class MyPlugin(Plugin):
        name = "my_plugin"
        version = "1.0.0"

        def on_register(self, ctx: PluginContext) -> None:
            ctx.add_router(my_router)

Lifecycle
---------
1. Discovery  — scan ``plugins/`` dir + entry-points
2. Validation  — check ``name``, ``version``, subclass of Plugin
3. Resolution  — topological sort by ``depends`` list
4. Registration — call ``on_register(ctx)`` in order
5. Startup     — call ``on_startup()`` (called from FastAPI lifespan)
6. Shutdown    — call ``on_shutdown()`` (called from FastAPI lifespan)
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from fastapi import FastAPI
from fastapi.routing import APIRouter

logger = logging.getLogger("logsoc.plugins")

# ---------------------------------------------------------------------------
# Public API — Plugin base class & context
# ---------------------------------------------------------------------------

@dataclass
class PluginContext:
    """Context handed to plugins during registration.

    Provides helpers to attach routers, access settings, etc.
    """
    app: FastAPI
    _routers: List[APIRouter] = field(default_factory=list)
    _settings: Dict[str, Any] = field(default_factory=dict)

    def add_router(self, router: APIRouter) -> None:
        """Register a FastAPI router; will be mounted on the app after all plugins register."""
        self._routers.append(router)

    def get_setting(self, key: str, default: Any = None) -> Any:
        return self._settings.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        self._settings[key] = value


class Plugin:
    """Base class every LOGSOC plugin must subclass.

    Attributes:
        name:      unique plugin identifier (required)
        version:   semver string (required)
        depends:   list of plugin names this plugin depends on
        description: short human-readable description
    """
    name: str = ""
    version: str = "0.0.0"
    depends: List[str] = []
    description: str = ""

    def on_register(self, ctx: PluginContext) -> None:
        """Called during app startup. Use ``ctx.add_router()`` to extend the API."""

    def on_startup(self) -> None:
        """Called after FastAPI lifespan starts (after ``on_register`` for all plugins)."""

    def on_shutdown(self) -> None:
        """Called when FastAPI shuts down."""


# ---------------------------------------------------------------------------
# Plugin discovery & loading
# ---------------------------------------------------------------------------

PLUGIN_DIR = Path(os.environ.get("LOGSOC_PLUGIN_DIR", "plugins"))


def _discover_directory(plugin_dir: Path) -> List[Type[Plugin]]:
    """Discover plugins from ``plugin_dir`` (Python packages or single .py files)."""
    plugins: List[Type[Plugin]] = []
    if not plugin_dir.is_dir():
        return plugins

    for entry in sorted(plugin_dir.iterdir()):
        module_name: Optional[str] = None
        spec: Optional[Any] = None

        if entry.is_dir() and (entry / "__init__.py").exists():
            spec = importlib.util.spec_from_file_location(
                f"logsoc_plugin_{entry.name}",
                str(entry / "__init__.py"),
                submodule_search_locations=[str(entry)],
            )
            module_name = f"logsoc_plugin_{entry.name}"
        elif entry.is_file() and entry.suffix == ".py":
            spec = importlib.util.spec_from_file_location(
                f"logsoc_plugin_{entry.stem}",
                str(entry),
            )
            module_name = f"logsoc_plugin_{entry.stem}"

        if spec is None or module_name is None:
            continue

        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception:
            logger.exception("Failed to load plugin module %s", module_name)
            continue

        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, Plugin) and obj is not Plugin and obj.name:
                plugins.append(obj)
                logger.info("Discovered plugin %s v%s from %s", obj.name, obj.version, entry.name)

    return plugins


def _discover_entry_points() -> List[Type[Plugin]]:
    """Discover plugins from ``logsoc.plugins`` entry-point group (if available)."""
    plugins: List[Type[Plugin]] = []
    try:
        from importlib.metadata import entry_points  # Python 3.9+
        eps = entry_points()
        if hasattr(eps, "select"):  # Python 3.12+
            group = eps.select(group="logsoc.plugins")
        else:
            group = eps.get("logsoc.plugins", [])  # type: ignore[assignment]
        for ep in group:
            try:
                obj = ep.load()
                if inspect.isclass(obj) and issubclass(obj, Plugin) and obj is not Plugin and obj.name:
                    plugins.append(obj)
            except Exception:
                logger.exception("Failed to load entry-point plugin %s", ep.name)
    except Exception:
        # importlib.metadata may not be available or no entry points
        pass
    return plugins


def _topo_sort(plugins: List[Type[Plugin]]) -> List[Type[Plugin]]:
    """Topological sort of plugins based on ``depends``."""
    by_name: Dict[str, Type[Plugin]] = {p.name: p for p in plugins}
    visited: set = set()
    order: List[Type[Plugin]] = []

    def _visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        if name in by_name:
            for dep in by_name[name].depends:
                _visit(dep)
            order.append(by_name[name])

    for p in plugins:
        _visit(p.name)
    return order


# ---------------------------------------------------------------------------
# Plugin Manager
# ---------------------------------------------------------------------------

class PluginManager:
    """Main plugin manager — discovers, validates, and registers plugins."""

    def __init__(self, app: FastAPI, plugin_dir: Optional[Path] = None) -> None:
        self.app = app
        self.plugin_dir = plugin_dir or PLUGIN_DIR
        self._plugins: List[Plugin] = []
        self._ctx = PluginContext(app=app)

    def discover_and_register(self) -> None:
        """Discover plugins, sort, validate, and register them."""
        all_classes = _discover_directory(self.plugin_dir) + _discover_entry_points()

        if not all_classes:
            logger.info("No plugins discovered")
            return

        # Deduplicate by name (later entries override earlier)
        seen: Dict[str, Type[Plugin]] = {}
        for cls in all_classes:
            if cls.name in seen:
                logger.warning("Duplicate plugin name %s, using last discovered", cls.name)
            seen[cls.name] = cls

        sorted_classes = _topo_sort(list(seen.values()))

        for cls in sorted_classes:
            logger.info("Registering plugin %s v%s", cls.name, cls.version)
            instance = cls()
            instance.on_register(self._ctx)
            self._plugins.append(instance)

        # Mount all collected routers with /api/v1/plugin/<name> prefix
        for router in self._ctx._routers:
            self.app.include_router(router)
            logger.info("Mounted plugin router with %d routes", len(router.routes))

        logger.info("Registered %d plugins", len(self._plugins))

    def on_startup(self) -> None:
        for p in self._plugins:
            try:
                p.on_startup()
            except Exception:
                logger.exception("Plugin %s on_startup failed", p.name)

    def on_shutdown(self) -> None:
        for p in reversed(self._plugins):
            try:
                p.on_shutdown()
            except Exception:
                logger.exception("Plugin %s on_shutdown failed", p.name)

    @property
    def plugins(self) -> List[Plugin]:
        return list(self._plugins)


# ---------------------------------------------------------------------------
# Convenience: integrate into FastAPI lifespan
# ---------------------------------------------------------------------------

def setup_plugins(app: FastAPI, plugin_dir: Optional[Path] = None) -> PluginManager:
    """Create a PluginManager, discover/register plugins, and wire lifecycle hooks."""
    manager = PluginManager(app, plugin_dir)

    # Discover & register before app starts
    manager.discover_and_register()

    # Hook into lifespan for startup/shutdown
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def combined_lifespan(app_instance: FastAPI):  # type: ignore[misc]
        manager.on_startup()
        if original_lifespan:
            async with original_lifespan(app_instance):  # type: ignore[arg-type]
                yield
        else:
            yield
        manager.on_shutdown()

    app.router.lifespan_context = combined_lifespan
    return manager


# Single import needed for convenience
from contextlib import asynccontextmanager  # noqa: E402