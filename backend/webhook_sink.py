import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LAST = {
    "ts": None,
    "method": None,
    "path": None,
    "headers": None,
    "body": None,
}

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/last"):
            return self._send_json(LAST, 200)
        return self._send_json({"ok": True, "hint": "POST anything, then GET /last"}, 200)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = repr(body)

        LAST["ts"] = time.time()
        LAST["method"] = "POST"
        LAST["path"] = self.path
        LAST["headers"] = {k: v for k, v in self.headers.items()}
        LAST["body"] = body_text

        # Print to container logs (easy to view)
        print("\n=== WEBHOOK SINK RECEIVED ===")
        print("PATH:", self.path)
        print("HEADERS:", json.dumps(LAST["headers"], indent=2))
        print("BODY:", body_text[:2000])
        print("=== END ===\n")

        return self._send_json({"ok": True}, 200)

    def log_message(self, format, *args):
        # silence default http server logs
        return


def main():
    host = "0.0.0.0"
    port = 9001
    httpd = HTTPServer((host, port), Handler)
    print(f"Webhook sink listening on http://{host}:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
