"""Security and Authentication tests."""
import pytest
from fastapi.testclient import TestClient
from app.core.auth import create_demo_token
from app.core.config import Settings
from app.main import app
from app.services.llm_advisor import redact_sensitive


@pytest.fixture
def client():
    return TestClient(app)


def test_unauthenticated_requests_rejected(client):
    # Protected endpoint without Authorization header must return 401
    resp = client.get("/api/snapshots")
    assert resp.status_code == 401
    assert "Authorization" in resp.json().get("detail", "")

    diffs_resp = client.get("/api/diffs")
    assert diffs_resp.status_code == 401


def test_role_based_access_denial(client):
    # Viewer token should be rejected on operator-only POST /api/snapshots
    viewer_token = create_demo_token(username="viewer-user", role="viewer")
    headers = {"Authorization": f"Bearer {viewer_token}"}

    resp = client.post(
        "/api/snapshots",
        json={"name": "test-snap", "cloud_provider": "aws", "assets": []},
        headers=headers,
    )
    assert resp.status_code == 403
    assert "operator" in resp.json().get("detail", "")


def test_admin_role_enforcement(client):
    # Operator token cannot delete snapshot
    operator_token = create_demo_token(username="op-user", role="operator")
    headers = {"Authorization": f"Bearer {operator_token}"}

    resp = client.delete("/api/snapshots/some-id", headers=headers)
    assert resp.status_code == 403
    assert "admin" in resp.json().get("detail", "")


def test_production_mode_refuses_demo_mode():
    with pytest.raises(ValueError, match="DEMO_MODE must NEVER be enabled in production"):
        Settings(ENVIRONMENT="production", DEMO_MODE=True)


def test_redact_sensitive_strings():
    # Construct synthetic runtime secret without literal token patterns
    synthetic_secret = "Bearer " + ("mocktoken" * 4)
    log_line = f"Authentication header encountered: {synthetic_secret}"
    redacted = redact_sensitive(log_line)
    assert "[REDACTED]" in redacted
    assert ("mocktoken" * 4) not in redacted


def test_demo_token_response_envelope(client):
    """The demo-token envelope (access_token/role/username) must match the typed
    frontend client's mapping contract so login persists a real session."""
    resp = client.post(
        "/api/auth/demo-token", json={"role": "viewer", "username": "alice"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]  # non-empty signed token
    assert body["role"] == "viewer"  # role forwarded from request
    assert body["username"] == "alice"  # username forwarded from request
    assert "expires_in" in body and isinstance(body["expires_in"], int)
