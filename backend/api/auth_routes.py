"""
auth_routes.py – Authentication API endpoints.

POST /api/auth/register  → register a new user
POST /api/auth/login     → login, returns bearer token
POST /api/auth/logout    → revoke token
GET  /api/auth/me        → return current user info (token validation)
"""

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel
from typing import Optional
from core.auth import create_user, verify_user, create_token, validate_token, revoke_token

auth_router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / Response models ─────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    username: str
    message: str


class UserInfo(BaseModel):
    username: str
    user_id: int


# ── Helper ────────────────────────────────────────────────────────────────────

def _extract_token(authorization: Optional[str]) -> str:
    """Extract Bearer token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    return authorization[len("Bearer "):]


def require_auth(
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> dict:
    """
    Dependency: validate token and return user info.
    Accepts Bearer token in Authorization header or 'token' query parameter.
    Raises 401 if token is missing or invalid.
    """
    raw_token = None
    if isinstance(authorization, str) and authorization.startswith("Bearer "):
        raw_token = authorization[len("Bearer "):].strip()
    elif isinstance(token, str) and token.strip():
        raw_token = token.strip()

    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token.")

    user = validate_token(raw_token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    return user


# ── Endpoints ─────────────────────────────────────────────────────────────────

@auth_router.post("/register", response_model=TokenResponse)
def register(body: RegisterRequest):
    """Register a new user and return a session token."""
    result = create_user(body.username, body.password)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["error"])

    # Auto-login after successful registration
    verify = verify_user(body.username, body.password)
    if not verify["ok"]:
        raise HTTPException(status_code=500, detail="Registration succeeded but auto-login failed.")

    token = create_token(verify["user_id"], verify["username"])
    return TokenResponse(token=token, username=verify["username"], message="Registration successful.")


@auth_router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    """Authenticate and return a bearer token."""
    result = verify_user(body.username, body.password)
    if not result["ok"]:
        raise HTTPException(status_code=401, detail=result["error"])

    token = create_token(result["user_id"], result["username"])
    return TokenResponse(token=token, username=result["username"], message="Login successful.")


@auth_router.post("/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    """Revoke the current bearer token."""
    token = _extract_token(authorization)
    revoke_token(token)
    return {"message": "Logged out successfully."}


@auth_router.get("/me", response_model=UserInfo)
def me(authorization: Optional[str] = Header(default=None)):
    """Return the current user's info (useful for frontend to check login state)."""
    token = _extract_token(authorization)
    user = validate_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return UserInfo(username=user["username"], user_id=user["user_id"])
