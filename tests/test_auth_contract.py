import os
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = f"sqlite:///{Path(tempfile.gettempdir()) / 'centinela_auth_contract_test.db'}"
os.environ.setdefault("SECRET_KEY", "centinela-test-secret")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "centinela-local-dev-password-change-me"

from fastapi.testclient import TestClient

from main import app


ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
PROTECTED_ENDPOINTS = [
    "/api/v1/auth/me",
    "/api/v1/incidents",
    "/api/v1/policy/all",
    "/api/v1/agents/stats",
    "/api/v1/resilience/degraded-runtime",
    "/api/v1/governance/runtime-trust",
]


def login(client: TestClient, password: str = ADMIN_PASSWORD):
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": password},
    )


def test_login_contract_accepts_admin_username_and_env_password():
    with TestClient(app) as client:
        response = login(client)

    assert response.status_code == 200
    payload = response.json()
    assert payload["access_token"]
    assert payload["token"]
    assert payload["token_type"] == "bearer"
    assert payload["username"] == "admin"
    assert payload["role"] == "admin"
    assert payload["is_admin"] is True


def test_login_contract_rejects_incorrect_password():
    with TestClient(app) as client:
        response = login(client, "wrong-password")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_login_contract_rejects_incomplete_payload():
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json={"password": ADMIN_PASSWORD})

    assert response.status_code == 400
    assert response.json()["detail"] == "Username and password required"


def test_cors_preflight_allows_production_frontend_origin():
    with TestClient(app) as client:
        response = client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "https://centinela-alpha.vercel.app",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,authorization",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://centinela-alpha.vercel.app"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_auth_me_rejects_invalid_token():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert response.status_code == 401


def test_protected_endpoints_require_bearer_token():
    with TestClient(app) as client:
        for endpoint in PROTECTED_ENDPOINTS:
            response = client.get(endpoint)
            assert response.status_code == 401


def test_protected_endpoints_accept_valid_bearer_token():
    with TestClient(app) as client:
        token = login(client).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["username"] == "admin"

        for endpoint in PROTECTED_ENDPOINTS[1:]:
            response = client.get(endpoint, headers=headers)
            assert response.status_code == 200
