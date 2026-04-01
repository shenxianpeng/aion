from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import InboxItem, OrchestrationEvent


class EventInbox:
    def __init__(self, root: Path):
        self.root = root
        self.events_dir = self.root / "events"
        self.results_dir = self.root / "results"
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def enqueue(self, event: OrchestrationEvent) -> InboxItem:
        item = InboxItem(
            item_id=self._item_id(event),
            status="pending",
            event=event,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._write_item(item)
        return item

    def list_items(self, status: str | None = None) -> list[InboxItem]:
        items: list[InboxItem] = []
        for path in sorted(self.events_dir.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            item = InboxItem(**payload)
            if status is not None and item.status != status:
                continue
            items.append(item)
        return items

    def get_item(self, item_id: str) -> InboxItem | None:
        path = self.events_dir / f"{item_id}.json"
        if not path.exists():
            return None
        return InboxItem(**json.loads(path.read_text(encoding="utf-8")))

    def mark_processed(self, item: InboxItem, result_path: Path) -> InboxItem:
        updated = item.model_copy(
            update={
                "status": "processed",
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "result_path": str(result_path),
                "error": None,
            }
        )
        self._write_item(updated)
        return updated

    def mark_failed(self, item: InboxItem, error: str) -> InboxItem:
        updated = item.model_copy(
            update={
                "status": "failed",
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "error": error,
            }
        )
        self._write_item(updated)
        return updated

    def result_file(self, item: InboxItem) -> Path:
        return self.results_dir / f"{item.item_id}.json"

    def _write_item(self, item: InboxItem) -> None:
        path = self.events_dir / f"{item.item_id}.json"
        tmp_path = self.events_dir / f"{item.item_id}.json.tmp"
        tmp_path.write_text(item.model_dump_json(indent=2), encoding="utf-8")
        tmp_path.replace(path)

    def _item_id(self, event: OrchestrationEvent) -> str:
        digest = hashlib.sha256(f"{event.event_id}:{event.target_file}".encode("utf-8")).hexdigest()
        return digest[:16]
