import json
import threading
import urllib.request
from pathlib import Path

from aion.inbox import EventInbox
from aion.webhook import WebhookEventServer


def test_webhook_server_enqueues_event(tmp_path: Path) -> None:
    inbox_root = tmp_path / "inbox"
    server = WebhookEventServer(("127.0.0.1", 0), inbox_root)
    server.max_events = 1

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps({"event_type": "runtime_alert", "target_file": "/tmp/demo.py"}).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/events",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
        assert body["status"] == "pending"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    items = EventInbox(inbox_root).list_items(status="pending")
    assert len(items) == 1
    assert items[0].event.event_type == "runtime_alert"
