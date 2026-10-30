# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Alerter webhook delivery — a 3xx must surface as a failed delivery and
must never be followed (a redirect would re-POST the alert payload to a
foreign host)."""
import http.server
import threading
from unittest.mock import MagicMock

import filescanner as fs


def test_webhook_does_not_follow_redirect():
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            if self.path == "/hook":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/hook"
        logger = MagicMock()
        a = fs.Alerter({"malicious"}, None, url, None, False, logger)
        a._to_webhook({"classification": "malicious"})
        # Only /hook was hit — the 302 was never followed to /elsewhere —
        # and the delivery was logged as a failure like any other error.
        assert hits == ["/hook"]
        logger.error.assert_called_once()
    finally:
        srv.shutdown()
        srv.server_close()


def test_webhook_posts_payload():
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            hits.append((self.path, self.rfile.read(n)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/hook"
        logger = MagicMock()
        a = fs.Alerter({"malicious"}, None, url, None, False, logger)
        a._to_webhook({"classification": "malicious"})
        assert [h[0] for h in hits] == ["/hook"]
        assert b"malicious" in hits[0][1]
        logger.error.assert_not_called()
    finally:
        srv.shutdown()
        srv.server_close()
