# Access and defences: ownership, roles, API keys, CORS, rate limiting.

from app import config
from tests.conftest import bearer, login


def test_users_see_only_their_own_transactions(client, alice):
    ben = login(client, "ben", config.DEMO_USER_PASSWORD).json()
    alice_refs = {t["reference"] for t in client.get("/transactions/me", headers=bearer(alice["access_token"])).json()}
    ben_refs = {t["reference"] for t in client.get("/transactions/me", headers=bearer(ben["access_token"])).json()}
    assert alice_refs and ben_refs                   # both have transactions
    assert not alice_refs & ben_refs                 # none are shared


def test_normal_user_gets_403_on_admin_route(client, alice):
    r = client.get("/admin/transactions", headers=bearer(alice["access_token"]))
    assert r.status_code == 403


def test_admin_can_open_admin_route(client, admin):
    r = client.get("/admin/transactions", headers=bearer(admin["access_token"]))
    assert r.status_code == 200


def test_valid_api_key_opens_service_route(client):
    r = client.get("/service/ledger-summary", headers={"X-API-Key": config.API_KEYS[0]})
    assert r.status_code == 200


def test_missing_or_wrong_api_key_is_rejected(client):
    assert client.get("/service/ledger-summary").status_code == 401
    assert client.get("/service/ledger-summary", headers={"X-API-Key": "guessed-1234"}).status_code == 401


def test_cors_trusts_only_listed_origin(client):
    ask = {"Access-Control-Request-Method": "GET"}
    trusted = client.options("/users/me", headers={**ask, "Origin": "http://localhost:3000"})
    unknown = client.options("/users/me", headers={**ask, "Origin": "https://evil-site.com"})
    assert trusted.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in unknown.headers


def test_login_is_rate_limited(client):
    codes = [login(client, "alice", "wrong-password").status_code for _ in range(6)]
    assert codes == [401, 401, 401, 401, 401, 429]   # 5 tries allowed, the 6th blocked