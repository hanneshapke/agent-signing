"""Google Sign-in (OIDC) and personal upload tokens for the registry.

Design B (token-centric): users authenticate with Google in the browser, then
mint a personal token that the CLI/SDK attaches to uploads.  The registry
resolves that token to the Google-verified identity and stamps the record, so a
"verified submitter" cannot be forged from user input.

Everything here degrades gracefully: if ``authlib`` is not installed or the
Google client credentials are unset, sign-in is reported as disabled and the
``/auth/login`` flow returns 503 — token-based stamping of *existing* tokens
still works, and the rest of the registry is unaffected.
"""

import hashlib
import os
import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from .database import create_token, delete_token, get_token_identity, list_tokens

# ---------------------------------------------------------------------------
# Configuration (all via environment)
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.environ.get(
    "OAUTH_REDIRECT_URI", "http://localhost:8000/auth/callback"
)
# Optional: restrict sign-in to a single Google Workspace domain (the `hd` claim).
ALLOWED_HD = os.environ.get("GOOGLE_ALLOWED_HD")
# Secret used to sign session cookies; ephemeral (per-process) if unset.
SESSION_SECRET = os.environ.get("REGISTRY_SESSION_SECRET") or secrets.token_hex(32)

_CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"
_TOKEN_PREFIX = "ast_"

# ---------------------------------------------------------------------------
# OAuth client (guarded — optional dependency)
# ---------------------------------------------------------------------------
oauth: Any = None
try:
    from authlib.integrations.starlette_client import OAuth

    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        oauth = OAuth()
        oauth.register(
            name="google",
            server_metadata_url=_CONF_URL,
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            client_kwargs={"scope": "openid email profile"},
        )
except ImportError:
    oauth = None


def auth_enabled() -> bool:
    """True when Google sign-in is fully configured and available."""
    return oauth is not None


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def identity_from_bearer(authorization: str | None) -> dict[str, Any] | None:
    """Resolve an ``Authorization: Bearer <token>`` header to a Google identity.

    Returns ``None`` for missing/malformed/unknown tokens (anonymous upload).
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None
    return get_token_identity(_hash_token(token))


def _current_user(request: Request) -> dict[str, Any] | None:
    return request.session.get("user")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class TokenMintRequest(BaseModel):
    label: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me")
async def me(request: Request) -> dict[str, Any]:
    """Report whether sign-in is enabled and who (if anyone) is signed in."""
    return {"enabled": auth_enabled(), "user": _current_user(request)}


@router.get("/login")
async def login(request: Request):
    if not auth_enabled():
        raise HTTPException(503, "Google sign-in is not configured on this registry.")
    return await oauth.google.authorize_redirect(request, OAUTH_REDIRECT_URI)


@router.get("/callback")
async def callback(request: Request):
    if not auth_enabled():
        raise HTTPException(503, "Google sign-in is not configured.")
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as exc:  # noqa: BLE001 - surface any OAuth failure as 400
        raise HTTPException(400, f"OAuth callback failed: {exc}") from exc

    info = token.get("userinfo") or {}
    email = info.get("email")
    if not email or not info.get("email_verified", False):
        raise HTTPException(403, "Google account has no verified email address.")
    if ALLOWED_HD and info.get("hd") != ALLOWED_HD:
        raise HTTPException(403, f"Sign-in is restricted to the {ALLOWED_HD} domain.")

    request.session["user"] = {
        "email": email,
        "sub": info.get("sub"),
        "name": info.get("name"),
        "picture": info.get("picture"),
    }
    return RedirectResponse(url="/")


@router.post("/logout")
async def logout(request: Request) -> dict[str, bool]:
    request.session.pop("user", None)
    return {"ok": True}


@router.post("/tokens")
async def mint_token(request: Request, body: TokenMintRequest) -> dict[str, Any]:
    """Create a personal upload token bound to the signed-in Google identity."""
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "Sign in with Google first.")
    token = _TOKEN_PREFIX + secrets.token_urlsafe(32)
    prefix = token[:12]
    rec = create_token(
        token_hash=_hash_token(token),
        prefix=prefix,
        email=user["email"],
        sub=user.get("sub"),
        name=user.get("name"),
        label=body.label,
    )
    # The full token is returned exactly once; only its hash is stored.
    return {
        "token": token,
        "id": rec["id"],
        "prefix": prefix,
        "label": body.label,
        "created_at": rec["created_at"],
    }


@router.get("/tokens")
async def get_tokens(request: Request) -> list[dict[str, Any]]:
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "Sign in with Google first.")
    return list_tokens(user["email"])


@router.delete("/tokens/{token_id}")
async def revoke_token(request: Request, token_id: int) -> dict[str, bool]:
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "Sign in with Google first.")
    if not delete_token(token_id, user["email"]):
        raise HTTPException(404, "Token not found.")
    return {"ok": True}
