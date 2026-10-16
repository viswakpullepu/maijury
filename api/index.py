"""
VERCEL SERVERLESS PYTHON ENTRYPOINT
Exposes FastAPI backend application to Vercel edge/serverless runtime.
Includes Vercel URL path resolution middleware to handle rewritten routing.
"""
import sys
import os

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.main import app

# ASGI Middleware to restore requested path from Vercel headers
class VercelPathMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            headers = dict(scope.get("headers", []))
            # x-matched-path or x-forwarded-path
            matched = headers.get(b"x-matched-path") or headers.get(b"x-now-route-matches")
            if matched:
                try:
                    scope["path"] = matched.decode("utf-8").split("?")[0]
                except Exception:
                    pass
            elif scope.get("path") == "/api/index.py":
                scope["path"] = "/"

        await self.app(scope, receive, send)

handler = VercelPathMiddleware(app)
