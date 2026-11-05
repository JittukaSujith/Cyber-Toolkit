#!/usr/bin/env python3
"""
Deliberately vulnerable practice target. Binds to 127.0.0.1 ONLY.

It has no real database or secrets; it just *simulates* common bugs so you can see what
the scanner detects, then read this file to learn how each bug is fixed:
  /search?q=...   reflects input without HTML-escaping (reflected XSS)
  /item?id=...    prints a fake SQL error when the input contains a quote
  /.env           fake exposed config file
  /login          POST form without CSRF token
Run:  python demo_vulnerable_server.py     then scan:  python web_scanner.py http://127.0.0.1:8081/
"""
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = "<html><body><h1>Demo Shop (intentionally vulnerable)</h1>{}</body></html>"


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.0"  # version disclosure on purpose

    def _send(self, body: str, status: int = 200, ctype: str = "text/html"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/":
            self._send(PAGE.format('<a href="/search?q=shoes">Search</a> <a href="/item?id=1">Item 1</a>'
                                   '<form action="/search" method="get"><input name="q" type="text"></form>'
                                   '<form action="/login" method="post"><input name="user"><input name="pw" type="password"></form>'))
        elif url.path == "/search":
            term = q.get("q", [""])[0]
            # VULNERABLE: user input is placed in HTML unescaped. FIX: html.escape(term)
            self._send(PAGE.format(f"<p>Results for: {term}</p><p>Safe version: {html.escape(term)}</p>"))
        elif url.path == "/item":
            item = q.get("id", ["1"])[0]
            if "'" in item:  # simulates a DB error leak. FIX: parameterized queries + generic errors
                self._send(PAGE.format("<pre>You have an error in your SQL syntax near ''' at line 1</pre>"), 500)
            else:
                self._send(PAGE.format(f"<p>Item {html.escape(item)}</p>"))
        elif url.path == "/.env":
            self._send("DB_PASSWORD=not-a-real-secret\n", ctype="text/plain")
        else:
            self._send(PAGE.format("Not found"), 404)

    def log_message(self, fmt, *args):
        print(f"[demo-server] {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    print("Vulnerable demo server on http://127.0.0.1:8081  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
