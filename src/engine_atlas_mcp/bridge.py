"""The local link between the site's edit mode and this MCP.

The site is static and has no accounts, so edits live with the person: in the browser
and in the MCP's edits file. While edit mode is connected, the page keeps them equal
through this endpoint. It listens on the loopback only and answers only the Atlas site.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

PORT = 47615
LIMIT = 64*1024*1024
RETRY_SECONDS = 3


def handler_for(store, origin):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass

        def allowed(self):
            # A foreign page must not read or replace edits, and a rebound name must not pose as local.
            host = self.headers.get('Host', '').rsplit(':', 1)[0]
            return self.headers.get('Origin') == origin and host in ('127.0.0.1', 'localhost')

        def reply(self, status, value=None):
            body = b'' if value is None else json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            if self.allowed():
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'content-type')
                self.send_header('Access-Control-Allow-Private-Network', 'true')
                self.send_header('Vary', 'Origin')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.reply(204 if self.allowed() else 403)

        def do_GET(self):
            if not self.allowed(): return self.reply(403)
            if self.path != '/state': return self.reply(404)
            self.reply(200, store.read())

        def do_PUT(self):
            if not self.allowed(): return self.reply(403)
            if self.path != '/state': return self.reply(404)
            length = int(self.headers.get('Content-Length') or 0)
            if length > LIMIT: return self.reply(413)
            try:
                value = json.loads(self.rfile.read(length))
                edits = value['edits']
                if edits.get('version') != 1 or not isinstance(edits.get('cards'), dict): raise ValueError
                revision = int(value['baseRevision'])
            except (KeyError, TypeError, ValueError, AttributeError):
                return self.reply(400)
            accepted, state = store.replace(revision, edits)
            self.reply(200 if accepted else 409, state)
    return Handler


def serve(store, origin, port=PORT):
    server = ThreadingHTTPServer(('127.0.0.1', port), handler_for(store, origin))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def keep_serving(store, origin, port=PORT):
    """Several sessions share the port: when the holder closes, another takes over."""
    state = {'listening': False}

    def run():
        while True:
            try:
                server = ThreadingHTTPServer(('127.0.0.1', port), handler_for(store, origin))
            except OSError:
                time.sleep(RETRY_SECONDS)
                continue
            state['listening'] = True
            server.serve_forever()

    threading.Thread(target=run, daemon=True).start()
    return state
