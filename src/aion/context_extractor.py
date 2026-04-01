from __future__ import annotations

import ast
import hashlib
import json
import random
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from .models import ContextProfile, normalize_path

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
}
ORM_IMPORTS = ("sqlalchemy", "django.db", "peewee", "tortoise", "pony", "ormar")
HTTP_IMPORTS = ("httpx", "requests", "aiohttp", "urllib3")
LOW_LEVEL_DB_IMPORTS = ("sqlite3", "pymysql", "psycopg2", "mysql.connector", "MySQLdb")
DB_CALL_PATTERNS = {
    "session.query": "session.query()",
    "session.execute": "session.execute()",
    "db.execute": "db.execute()",
    "cursor.execute": "cursor.execute()",
    "Model.objects": "Model.objects",
}


@dataclass
class ExtractedFileData:
    imports: list[str]
    decorators: list[str]
    db_patterns: list[str]
    function_names: list[str]
    orm_candidates: list[str]
    http_candidates: list[str]
    low_level_db_imports: list[str]


class ContextExtractor:
    def __init__(
        self,
        root: Path,
        max_files: int = 500,
        cache_path: Path | None = None,
        extra_ignore_patterns: list[str] | None = None,
    ):
        self.root = root.resolve()
        self.max_files = max_files
        self.cache_path = cache_path or Path.home() / ".aion-context.json"
        self._cache = self._load_cache()
        self._ignore_patterns = self._load_gitignore_patterns()
        self._ignore_patterns.extend(extra_ignore_patterns or [])

    def extract(self) -> ContextProfile:
        python_files = self._collect_python_files()
        sampled = False
        if len(python_files) > self.max_files:
            sampled = True
            randomizer = random.Random(42)
            python_files = sorted(randomizer.sample(python_files, self.max_files))

        profile = ContextProfile(scanned_files=len(python_files), sampled=sampled)
        orm_votes: dict[str, int] = {}
        http_votes: dict[str, int] = {}
        import_set: set[str] = set()
        decorator_set: set[str] = set()
        db_pattern_set: set[str] = set()
        function_set: set[str] = set()
        low_level_set: set[str] = set()

        for file_path in python_files:
            cached = self._extract_with_cache(file_path)
            if cached is None:
                profile.skipped_files.append(normalize_path(file_path))
                continue
            import_set.update(cached.imports)
            decorator_set.update(cached.decorators)
            db_pattern_set.update(cached.db_patterns)
            function_set.update(cached.function_names)
            low_level_set.update(cached.low_level_db_imports)
            for orm in cached.orm_candidates:
                orm_votes[orm] = orm_votes.get(orm, 0) + 1
            for client in cached.http_candidates:
                http_votes[client] = http_votes.get(client, 0) + 1

        profile.imports = sorted(import_set)[:50]
        profile.auth_decorators = sorted(decorator_set)[:20]
        profile.db_patterns = sorted(db_pattern_set)[:20]
        profile.function_names = sorted(function_set)[:30]
        profile.low_level_db_imports = sorted(low_level_set)[:20]
        profile.orm = self._pick_top_vote(orm_votes)
        profile.http_client = self._pick_top_vote(http_votes)
        self._write_cache()
        return profile

    def _collect_python_files(self) -> list[Path]:
        files: list[Path] = []
        for path in self.root.rglob("*.py"):
            if any(part in DEFAULT_EXCLUDES for part in path.parts):
                continue
            relative = path.relative_to(self.root).as_posix()
            if self._is_ignored(relative):
                continue
            files.append(path)
        return sorted(files)

    def _is_ignored(self, relative_path: str) -> bool:
        for pattern in self._ignore_patterns:
            if fnmatch(relative_path, pattern) or fnmatch(Path(relative_path).name, pattern):
                return True
        return False

    def _load_gitignore_patterns(self) -> list[str]:
        gitignore = self.root / ".gitignore"
        if not gitignore.exists():
            return []
        patterns: list[str] = []
        for raw_line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            if line.endswith("/"):
                patterns.append(f"{line}*")
            patterns.append(line.lstrip("/"))
        return patterns

    def _extract_with_cache(self, file_path: Path) -> ExtractedFileData | None:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        cache_key = normalize_path(file_path)
        cached = self._cache.get(cache_key)
        if cached and cached.get("sha256") == digest:
            try:
                return ExtractedFileData(**cached["data"])
            except TypeError:
                pass

        parsed = self._extract_file(file_path, content)
        if parsed is None:
            return None
        self._cache[cache_key] = {"sha256": digest, "data": parsed.__dict__}
        return parsed

    def _extract_file(self, file_path: Path, content: str) -> ExtractedFileData | None:
        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return None

        imports: set[str] = set()
        decorators: set[str] = set()
        db_patterns: set[str] = set()
        function_names: set[str] = set()
        orm_candidates: set[str] = set()
        http_candidates: set[str] = set()
        low_level_db_imports: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
                    self._classify_import(alias.name, orm_candidates, http_candidates, low_level_db_imports)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module:
                    imports.add(module)
                    self._classify_import(module, orm_candidates, http_candidates, low_level_db_imports)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_names.add(node.name)
                for decorator in node.decorator_list:
                    rendered = self._render_name(decorator)
                    if rendered:
                        decorators.add(f"@{rendered}")
            elif isinstance(node, ast.Call):
                rendered = self._render_name(node.func)
                if rendered and rendered in DB_CALL_PATTERNS:
                    db_patterns.add(DB_CALL_PATTERNS[rendered])

        return ExtractedFileData(
            imports=sorted(imports),
            decorators=sorted(decorators),
            db_patterns=sorted(db_patterns),
            function_names=sorted(function_names),
            orm_candidates=sorted(orm_candidates),
            http_candidates=sorted(http_candidates),
            low_level_db_imports=sorted(low_level_db_imports),
        )

    def _classify_import(
        self,
        module_name: str,
        orm_candidates: set[str],
        http_candidates: set[str],
        low_level_db_imports: set[str],
    ) -> None:
        lowered = module_name.lower()
        for orm in ORM_IMPORTS:
            if lowered.startswith(orm):
                orm_candidates.add(orm.split(".")[0])
        for client in HTTP_IMPORTS:
            if lowered.startswith(client):
                http_candidates.add(client)
        for db_import in LOW_LEVEL_DB_IMPORTS:
            if lowered.startswith(db_import.lower()):
                low_level_db_imports.add(db_import)

    def _render_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._render_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._render_name(node.func)
        return None

    def _pick_top_vote(self, votes: dict[str, int]) -> str | None:
        if not votes:
            return None
        return sorted(votes.items(), key=lambda item: (-item[1], item[0]))[0][0]

    def _load_cache(self) -> dict[str, dict[str, object]]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_cache(self) -> None:
        try:
            self.cache_path.write_text(
                json.dumps(self._cache, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            pass
