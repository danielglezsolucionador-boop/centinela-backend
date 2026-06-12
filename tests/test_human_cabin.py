import json
import os
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = f"sqlite:///{Path(tempfile.gettempdir()) / 'centinela_human_cabin_test.db'}"
os.environ.setdefault("SECRET_KEY", "centinela-test-secret")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "centinela-local-dev-password-change-me")

from fastapi.testclient import TestClient

from main import app


_AUTH_HEADERS: dict | None = None


def auth_headers(client: TestClient) -> dict:
    global _AUTH_HEADERS
    if _AUTH_HEADERS is not None:
        return _AUTH_HEADERS
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    _AUTH_HEADERS = {"Authorization": f"Bearer {token}"}
    return _AUTH_HEADERS


def test_human_cabin_requires_auth():
    with TestClient(app) as client:
        response = client.get("/api/v1/human-cabin/summary")
        assert response.status_code == 401


def test_human_cabin_summary_and_pricing():
    with TestClient(app) as client:
        headers = auth_headers(client)
        response = client.get("/api/v1/human-cabin/summary", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "DEMO_LOCAL"
        assert body["plans"][0]["price_label"] == "S/199/mes"
        assert any(plan["price_label"] == "S/499/mes" for plan in body["plans"])
        assert any(plan["price_label"] == "desde S/999/mes" for plan in body["plans"])
        assert body["client_visibility_policy"]["protected_internal_sources_exposed"] is False


def test_client_view_hides_protected_internal_source_and_ceo_admin_access():
    with TestClient(app) as client:
        headers = auth_headers(client)
        response = client.get("/api/v1/human-cabin/client-view", headers=headers)
        assert response.status_code == 200
        text = json.dumps(response.json(), ensure_ascii=False).lower()
        assert "sombra" not in text
        assert "admin" not in response.json()["visibility_policy"]
        assert response.json()["visibility_policy"]["ceo_public_access"] is False


def test_human_action_registers_audit_event():
    with TestClient(app) as client:
        headers = auth_headers(client)
        action = client.post(
            "/api/v1/human-cabin/requests/HC-HIGH-001/pause",
            headers=headers,
            json={"notes": "Pausa validada en prueba local."},
        )
        assert action.status_code == 200
        assert action.json()["request"]["status"] == "paused"
        audit = client.get("/api/v1/human-cabin/audit", headers=headers)
        assert audit.status_code == 200
        assert any(event["action"] == "pause" for event in audit.json())


def test_sensitive_action_is_blocked_by_default():
    with TestClient(app) as client:
        headers = auth_headers(client)
        response = client.post(
            "/api/v1/human-cabin/requests",
            headers=headers,
            json={
                "title": "Intento de acción irreversible",
                "severity": "critical",
                "action_type": "delete_data",
                "proposed_action": "borrar datos del sistema",
                "target_system": "Infraestructura demo",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "blocked"
        assert "Acción no permitida" in body["proposed_action"]


def test_frontend_human_cabin_claims_are_safe():
    frontend_root = Path(r"C:\Users\admin\Desktop\centinela")
    page = (frontend_root / "app" / "human-cabin" / "page.tsx").read_text(encoding="utf-8")
    login = (frontend_root / "app" / "login" / "page.tsx").read_text(encoding="utf-8")
    assert "Sombra" not in page
    assert "Entrar como CEO" not in login
    assert "modo CEO" not in login
    assert "Pago real pendiente" in page
    assert "DEMO_LOCAL" in page
