"""
test_auth.py – Tests for authentication logic and API route guards.
"""

import pytest
import sqlite3
from core import auth
from core.auth import (
    init_auth_tables,
    create_user,
    verify_user,
    create_token,
    validate_token,
    revoke_token,
)


import tempfile
import os

@pytest.fixture(autouse=True)
def setup_auth_db(monkeypatch):
    # Use isolated temp database for tests so real ipsec_history.db is never touched
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    monkeypatch.setattr(auth, "SQLITE_DB_PATH", temp_db_path)
    init_auth_tables()
    yield
    try:
        os.remove(temp_db_path)
    except Exception:
        pass


class TestAuthCore:
    def test_create_user_success(self):
        res = create_user("alice", "supersecret123")
        assert res["ok"] is True
        assert res["username"] == "alice"

    def test_create_user_short_username(self):
        res = create_user("al", "supersecret123")
        assert res["ok"] is False
        assert "Username must be at least 3 characters" in res["error"]

    def test_create_user_short_password(self):
        res = create_user("alice", "123")
        assert res["ok"] is False
        assert "Password must be at least 6 characters" in res["error"]

    def test_create_duplicate_user(self):
        res1 = create_user("bob_admin", "password123")
        assert res1["ok"] is True
        res2 = create_user("bob_admin", "anotherpass123")
        assert res2["ok"] is False
        assert "Username already taken" in res2["error"]

    def test_verify_user_success(self):
        create_user("charlie", "mypassword456")
        res = verify_user("charlie", "mypassword456")
        assert res["ok"] is True
        assert res["username"] == "charlie"
        assert isinstance(res["user_id"], int)

    def test_verify_user_wrong_password(self):
        create_user("charlie", "mypassword456")
        res = verify_user("charlie", "wrongpassword")
        assert res["ok"] is False
        assert res["error"] == "Invalid username or password."

    def test_verify_nonexistent_user(self):
        res = verify_user("ghost_user", "somepassword")
        assert res["ok"] is False
        assert res["error"] == "Invalid username or password."

    def test_token_lifecycle(self):
        create_user("token_user", "securepass")
        user = verify_user("token_user", "securepass")
        token = create_token(user["user_id"], user["username"])
        assert token is not None
        assert len(token) == 64  # 32 bytes hex

        # Validate valid token
        val = validate_token(token)
        assert val is not None
        assert val["username"] == "token_user"
        assert val["user_id"] == user["user_id"]

        # Revoke token
        revoked = revoke_token(token)
        assert revoked is True
        assert validate_token(token) is None


from api.auth_routes import (
    register,
    login,
    logout,
    me,
    require_auth,
    RegisterRequest,
    LoginRequest,
)
from fastapi import HTTPException


class TestAuthAPI:
    def test_register_and_login_api(self):
        # Register
        reg = register(RegisterRequest(username="apitester", password="password999"))
        assert reg.token is not None
        assert reg.username == "apitester"

        # Validate with me
        user_info = me(f"Bearer {reg.token}")
        assert user_info.username == "apitester"

        # Login again
        login_res = login(LoginRequest(username="apitester", password="password999"))
        assert login_res.token is not None

        # Logout
        logout_res = logout(f"Bearer {reg.token}")
        assert "Logged out" in logout_res["message"]

        # After logout, me should raise 401
        with pytest.raises(HTTPException) as exc_info:
            me(f"Bearer {reg.token}")
        assert exc_info.value.status_code == 401

    def test_protected_routes_require_auth(self):
        # Missing auth
        with pytest.raises(HTTPException) as exc1:
            require_auth(None)
        assert exc1.value.status_code == 401

        # Invalid token
        with pytest.raises(HTTPException) as exc2:
            require_auth("Bearer invalid_token_xyz")
        assert exc2.value.status_code == 401

        # Valid token via query param (e.g. for PDF downloads)
        user_res = verify_user("purva", "purva123")
        tok = create_token(user_res["user_id"], user_res["username"])
        auth_user = require_auth(authorization=None, token=tok)
        assert auth_user["username"] == "purva"
