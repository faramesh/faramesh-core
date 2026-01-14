# src/faramesh/server/auth.py
from __future__ import annotations

from typing import Optional

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .settings import get_settings


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for bearer token authentication."""
    
    def __init__(self, app, auth_token: Optional[str] = None):
        super().__init__(app)
        self.auth_token = auth_token or get_settings().auth_token
        self.public_paths = {
            "/",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/health",
            "/ready",
            "/metrics",
            "/app",
        }
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths (treat "/" as exact match only)
        if request.url.path == "/":
            return await call_next(request)
        if any(request.url.path.startswith(path) for path in self.public_paths if path != "/"):
            return await call_next(request)
        
        # Skip auth if no token configured
        if not self.auth_token:
            return await call_next(request)
        
        # Check Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header or not isinstance(auth_header, str):
            return Response(
                content='{"detail":"Missing or invalid Authorization header"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        if not auth_header.startswith("Bearer "):
            return Response(
                content='{"detail":"Missing or invalid Authorization header"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        token = auth_header.replace("Bearer ", "").strip()
        
        # Validate token is not empty
        if not token:
            return Response(
                content='{"detail":"Invalid authentication token"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        # Support multiple tokens (comma-separated) with defensive check
        if not self.auth_token or not isinstance(self.auth_token, str):
            return Response(
                content='{"detail":"Invalid authentication token"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        try:
            # Split and filter out empty tokens
            valid_tokens = [t.strip() for t in self.auth_token.split(",") if t and t.strip()]
        except (AttributeError, TypeError, ValueError):
            return Response(
                content='{"detail":"Invalid authentication token"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        if not valid_tokens or token not in valid_tokens:
            return Response(
                content='{"detail":"Invalid authentication token"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
        
        return await call_next(request)
