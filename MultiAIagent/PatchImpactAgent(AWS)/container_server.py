from __future__ import annotations

import json
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runtime_app import invoke


HOST = "0.0.0.0"
PORT = 8080


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class AgentCoreHandler(BaseHTTPRequestHandler):
    server_version = "PatchImpactAgent/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        print(f"[patch-impact-container] GET {self.path}", flush=True)
        if self.path == "/ping":
            _write_json(self, HTTPStatus.OK, {"status": "Healthy"})
            return
        _write_json(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        print(f"[patch-impact-container] POST {self.path}", flush=True)
        if self.path != "/invocations":
            _write_json(self, HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            _write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
            return

        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            _write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        if not isinstance(payload, dict):
            _write_json(self, HTTPStatus.BAD_REQUEST, {"error": "payload_must_be_object"})
            return

        try:
            result = invoke(payload)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[patch-impact-container] invocation failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            traceback.print_exc()
            _write_json(
                self,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            return

        if isinstance(result, dict):
            _write_json(self, HTTPStatus.OK, result)
            return

        _write_json(self, HTTPStatus.OK, {"result": result})


def main() -> None:
    print(f"[patch-impact-container] listening on {HOST}:{PORT}", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), AgentCoreHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
