from __future__ import annotations

import ast
from pathlib import Path

from .models import ContextProfile

ROUTE_DECORATOR_NAMES = {
    "app.get",
    "app.post",
    "app.put",
    "app.delete",
    "app.patch",
    "router.get",
    "router.post",
    "router.put",
    "router.delete",
    "router.patch",
}
SECRET_NAME_MARKERS = ("key", "secret", "token", "password")
LOW_LEVEL_DB_IMPORTS = {"sqlite3", "pymysql", "psycopg2", "mysql.connector", "mysqldb"}


def fallback_reasons(target: Path, context_profile: ContextProfile) -> list[str]:
    try:
        source = target.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(target))
    except (OSError, SyntaxError):
        return []

    reasons: list[str] = []
    if context_profile.orm and _imports_low_level_db(tree):
        reasons.append("low-level database access bypasses the project's ORM pattern")
    if _has_hardcoded_secret(tree):
        reasons.append("hardcoded secret-like assignment detected")
    if context_profile.auth_decorators and _has_route_without_auth(tree, context_profile.auth_decorators):
        reasons.append("route handler is missing the project's auth decorators")
    if _has_insecure_yaml_load(tree):
        reasons.append("yaml.load without SafeLoader allows arbitrary code execution via deserialization")
    if _has_os_system_injection(tree):
        reasons.append("os.system with f-string argument is vulnerable to command injection")
    return reasons


def _imports_low_level_db(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.lower() in LOW_LEVEL_DB_IMPORTS:
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").lower()
            if module in LOW_LEVEL_DB_IMPORTS:
                return True
    return False


def _has_hardcoded_secret(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = node.value
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            for target in node.targets:
                name = _render_name(target).lower()
                if any(marker in name for marker in SECRET_NAME_MARKERS):
                    return True
    return False


def _has_route_without_auth(tree: ast.AST, auth_decorators: list[str]) -> bool:
    allowed = {decorator.lstrip("@").split(".")[-1] for decorator in auth_decorators}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorator_names = {_render_name(decorator) for decorator in node.decorator_list}
        route_like = any(name in ROUTE_DECORATOR_NAMES for name in decorator_names if name)
        if not route_like:
            continue
        has_auth = any(name and name.split(".")[-1] in allowed for name in decorator_names)
        if not has_auth:
            return True
    return False


def _has_insecure_yaml_load(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _render_name(node.func)
            if name == "yaml.load":
                # Flag only when no Loader keyword argument is provided
                loader_kwarg = any(kw.arg == "Loader" for kw in node.keywords)
                if not loader_kwarg:
                    return True
    return False


def _has_os_system_injection(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _render_name(node.func)
            if name == "os.system" and node.args:
                if isinstance(node.args[0], ast.JoinedStr):
                    return True
    return False


def _render_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _render_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _render_name(node.func)
    return ""
