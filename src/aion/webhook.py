from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .inbox import EventInbox
from .orchestrator import Orchestrator


class WebhookEventServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], inbox_root: Path):
        self.inbox = EventInbox(inbox_root)
        self.orchestrator = Orchestrator()
        self.max_events: int | None = None
        self._events_processed = 0
        super().__init__(server_address, _build_handler(self))


def _build_handler(server: WebhookEventServer):
    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/events":
                self.send_error(404, "Not Found")
                return

            length_header = self.headers.get("Content-Length")
            if length_header is None:
                self.send_error(400, "Missing Content-Length header")
                return
            try:
                length = int(length_header)
            except ValueError:
                self.send_error(400, "Invalid Content-Length header")
                return
            if length < 0:
                self.send_error(400, "Invalid Content-Length header")
                return
            raw_body = self.rfile.read(length)
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON payload")
                return

            try:
                event = server.orchestrator.ingest_event(payload)
                item = server.inbox.enqueue(event)
            except Exception as exc:  # noqa: BLE001
                self.send_error(400, str(exc))
                return

            body = json.dumps({"item_id": item.item_id, "status": item.status}).encode("utf-8")
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

            server._events_processed += 1
            if server.max_events is not None and server._events_processed >= server.max_events:
                server.shutdown()

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    return WebhookHandler
