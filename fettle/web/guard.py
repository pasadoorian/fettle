"""Local Host and same-origin checks for HTTP *and* WebSocket traffic.

ASGI middleware surrounds NiceGUI's mounted Socket.IO app as well as its routes.
It uses no optional dependencies, allowing security tests in the core environment.
"""

from urllib.parse import urlsplit

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _authority(raw: str, scheme: str):
    try:
        parsed = urlsplit(f"{scheme}://{raw}")
        if (parsed.hostname not in LOCAL_HOSTS or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment):
            return None
        return parsed.hostname, parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None


class LocalOriginGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {}
        duplicate = False
        for key, value in scope.get("headers", []):
            key = key.lower()
            if key in (b"host", b"origin") and key in headers:
                duplicate = True
            headers[key] = value.decode("latin1")
        scheme = "https" if scope.get("scheme") in ("https", "wss") else "http"
        authority = _authority(headers.get(b"host", ""), scheme)
        origin = headers.get(b"origin")
        allowed = authority is not None and not duplicate
        if origin is not None:
            try:
                parsed = urlsplit(origin)
                allowed = (allowed and parsed.scheme == scheme
                           and _authority(parsed.netloc, parsed.scheme) == authority
                           and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                allowed = False
        elif scope["type"] == "websocket":
            allowed = False  # browsers always supply Origin for their handshake
        if headers.get(b"sec-fetch-site") == "cross-site":
            allowed = False
        if allowed:
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            body = b"fettle web is localhost-only and requires a same-origin request"
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": body})
