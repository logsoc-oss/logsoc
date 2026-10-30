"""PITFALL TEST (T74+T75.1, 2026-06-12) — static paths before path-param routes.

This test runs against all logsoc-web routers that mix static
and dynamic paths. It should pass on master. If it fails,
someone added a new path-param route ABOVE a static one
under the same prefix, and FastAPI will return 422 on the
static path until the order is fixed.

Reference: ~/.hermes/skills/logsoc/logsoc-web-fastapi/references/fastapi-routing-static-before-param.md
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTERS_DIR = os.path.join(HERE, "..", "app/routers")


def _analyze_routes(src: str):
    """Find all @router.METHOD("/path") decorators in order.

    Returns list of (line_no, path, is_param) tuples where
    is_param=True if the path contains a `/{...}` segment.
    """
    pattern = re.compile(
        r'@router\.(get|post|put|delete)\(\s*"([^"]+)"',
        re.MULTILINE,
    )
    routes = []
    for m in pattern.finditer(src):
        line_no = src[:m.start()].count('\n') + 1
        path = m.group(2)
        is_param = bool(re.search(r'/\{[^}]+\}', path))
        routes.append((line_no, path, is_param))
    return routes


def _common_prefix(p1: str, p2: str) -> str:
    """Return the longest common prefix of two paths.

    For routing purposes, we want the prefix up to the
    `/{param}` segment, inclusive of the trailing slash.
    e.g. /policy/audit/{audit_id} → /policy/audit/
    """
    parts1 = p1.split('/')
    parts2 = p2.split('/')
    common = []
    for a, b in zip(parts1, parts2):
        if a == b and '{' not in a:
            common.append(a)
        else:
            break
    return '/'.join(common) + '/' if common else '/'


class TestAllRoutersOrdering(unittest.TestCase):
    """For every router that has BOTH a static path and a
    path-param route under the same prefix, the static path
    must be declared FIRST (smaller line_no).
    """

    # Routers known to mix static + dynamic. T74: gdpr.py,
    # T75.1: agent_config.py. Add more as they're encountered.
    ROUTERS_TO_CHECK = [
        "agent_config.py",
        "gdpr.py",
    ]

    def setUp(self):
        self.routers = {}
        for fname in self.ROUTERS_TO_CHECK:
            path = os.path.join(ROUTERS_DIR, fname)
            if not os.path.exists(path):
                continue
            with open(path) as f:
                src = f.read()
            self.routers[fname] = (path, src)

    def test_static_paths_before_param_routes(self):
        """For every path-param route, find the FIRST static
        path with the same parent prefix. If the static path
        was declared AFTER the param route, FastAPI will
        422 on the static path (int/uuid converter swallows
        the segment without fallthrough).
        """
        for fname, (path, src) in self.routers.items():
            routes = _analyze_routes(src)
            # For each path-param route, find static routes
            # that share the parent prefix
            for line_no, param_path, is_param in routes:
                if not is_param:
                    continue
                # The parent prefix is everything up to (and
                # not including) the first `/{...}` segment
                m = re.search(r'/\{[^}]+\}', param_path)
                if not m:
                    continue
                parent = param_path[:m.start()]  # e.g. "/policy/audit"
                # Find any static route that EQUALS or is a
                # CHILD of the parent
                for s_line, s_path, s_is_param in routes:
                    if s_is_param:
                        continue  # skip param routes
                    # Static path is "under" the parent if it
                    # equals the parent or starts with parent + '/'
                    if s_path == parent or s_path.startswith(parent + '/'):
                        # Same prefix — must come BEFORE the param route
                        if s_line > line_no:
                            self.fail(
                                f"{fname}:{s_line}: static path "
                                f"'{s_path}' declared AFTER path-param "
                                f"route '{param_path}' (line {line_no}). "
                                f"FastAPI int/uuid converter returns "
                                f"422 on the static path without "
                                f"fallthrough. Move '{s_path}' "
                                f"ABOVE '{param_path}'."
                            )


if __name__ == "__main__":
    unittest.main()
