"""FR-1: password reset, self-service profile, admin user management."""
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed


def setup_module(_):
    Base.metadata.create_all(engine); seed()


client = TestClient(app)


def _admin():
    t = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"}).json()
    return {"Authorization": f"Bearer {t['access_token']}"}


def test_admin_creates_user_and_rbac():
    r = client.post("/api/users", headers=_admin(),
                    json={"name": "Carol", "email": "carol@socmind.io",
                          "password": "Analyst123!", "role": "SOC Analyst"})
    assert r.status_code == 201
    # analyst cannot list users
    t = client.post("/api/auth/login",
                    data={"username": "carol@socmind.io", "password": "Analyst123!"}).json()
    ah = {"Authorization": f"Bearer {t['access_token']}"}
    assert client.get("/api/users", headers=ah).status_code == 403
    # admin can
    assert client.get("/api/users", headers=_admin()).status_code == 200


def test_change_password_requires_current():
    client.post("/api/users", headers=_admin(),
                json={"name": "Dave", "email": "dave@socmind.io",
                      "password": "Analyst123!", "role": "Viewer"})
    t = client.post("/api/auth/login",
                    data={"username": "dave@socmind.io", "password": "Analyst123!"}).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert client.post("/api/auth/change-password", headers=h,
                       json={"current_password": "wrong", "new_password": "NewPass123!"}).status_code == 400
    assert client.post("/api/auth/change-password", headers=h,
                       json={"current_password": "Analyst123!", "new_password": "NewPass123!"}).status_code == 200


def test_forgot_and_reset_password_single_use():
    client.post("/api/users", headers=_admin(),
                json={"name": "Eve", "email": "eve@socmind.io",
                      "password": "Analyst123!", "role": "Viewer"})
    fr = client.post("/api/auth/forgot-password", json={"email": "eve@socmind.io"}).json()
    token = fr["dev_reset_link"].split("token=")[1]
    assert client.post("/api/auth/reset-password",
                       json={"token": token, "new_password": "Reset12345!"}).status_code == 200
    # single-use
    assert client.post("/api/auth/reset-password",
                       json={"token": token, "new_password": "Again12345!"}).status_code == 400
    # new password works
    assert client.post("/api/auth/login",
                       data={"username": "eve@socmind.io", "password": "Reset12345!"}).status_code == 200


def test_forgot_password_anti_enumeration():
    r = client.post("/api/auth/forgot-password", json={"email": "nobody@socmind.io"}).json()
    assert r["dev_reset_link"] is None          # no token for unknown account
    assert "reset link" in r["message"]          # but same generic message


def test_profile_update():
    t = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"}).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = client.patch("/api/auth/me", headers=h, json={"name": "Renamed Admin"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed Admin"
