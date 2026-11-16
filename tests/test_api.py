import json

from app.core.config import Settings, get_settings


def test_health_and_ready(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["database"] is True


def test_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    h = r.headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-request-id"]


def test_meta_exposes_no_secrets(client):
    meta = client.get("/api/v1/meta").json()
    assert meta["engine"] == "offline-deterministic"
    assert "key" not in json.dumps(meta).lower().replace("auth_required", "")


def test_analyze_persists_incident_and_hitl_flow(client):
    r = client.post("/api/v1/analyze", json={"message": "vssadmin delete shadows /all; files encrypted .locked"})
    assert r.status_code == 200
    body = r.json()
    incident_id = body["incident_id"]
    actions = body["report"]["actions"]
    gated = next(i for i, a in enumerate(actions) if a["requires_approval"])
    advisory = next(i for i, a in enumerate(actions) if not a["requires_approval"])

    ok = client.post(f"/api/v1/incidents/{incident_id}/decisions", json={"action_index": gated, "decision": "approved"})
    assert ok.status_code == 200
    assert ok.json()["decisions"][str(gated)]["decision"] == "approved"

    conflict = client.post(
        f"/api/v1/incidents/{incident_id}/decisions", json={"action_index": advisory, "decision": "approved"}
    )
    assert conflict.status_code == 409

    listed = client.get("/api/v1/incidents").json()
    assert any(i["id"] == incident_id for i in listed)
    assert client.get("/api/v1/stats").json()["total"] >= 1


def test_stream_endpoint_sse(client):
    with client.stream(
        "POST", "/api/v1/analyze/stream", json={"message": "Failed password for root from 1.2.3.4"}
    ) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        text = "".join(r.iter_text())
    assert "event: step" in text and "event: result" in text
    assert '"incident_id"' in text


def test_validation_rejects_oversized_input_without_echo(client):
    huge = "A" * 20_000
    r = client.post("/api/v1/analyze", json={"message": huge})
    assert r.status_code == 422
    assert huge not in r.text


def test_api_key_enforced_when_configured(client):
    client.app.dependency_overrides[get_settings] = lambda: Settings(api_keys="s3cret-key", rate_limit_per_minute=1000)
    try:
        assert client.get("/api/v1/incidents").status_code == 401
        assert client.get("/api/v1/incidents", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/api/v1/incidents", headers={"X-API-Key": "s3cret-key"}).status_code == 200
    finally:
        client.app.dependency_overrides.clear()


def test_rate_limiting(client):
    client.app.dependency_overrides[get_settings] = lambda: Settings(rate_limit_per_minute=2)
    try:
        codes = [client.post("/api/v1/analyze", json={"message": "hello there"}).status_code for _ in range(3)]
        assert codes[:2] == [200, 200] and codes[2] == 429
    finally:
        client.app.dependency_overrides.clear()


def test_production_config_fails_closed():
    import pytest

    with pytest.raises(RuntimeError):
        Settings(app_env="production", api_keys="", database_url="sqlite:///x.db").validate_production()
