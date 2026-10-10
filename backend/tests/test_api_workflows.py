"""End-to-end API workflows testing multi-cloud inventory lifecycle."""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_full_api_workflow(client):
    # 1. Healthcheck
    health_resp = client.get("/api/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"

    # 2. Acquire Operator Demo Token
    token_resp = client.post("/api/auth/demo-token", json={"role": "operator", "username": "alice"})
    assert token_resp.status_code == 200
    token = token_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Seed Sample Snapshots
    seed_resp = client.post("/api/snapshots/sample-seed", headers=auth_headers)
    assert seed_resp.status_code == 201
    seed_data = seed_resp.json()
    base_id = seed_data["base_snapshot_id"]
    target_id = seed_data["target_snapshot_id"]

    # 4. List Snapshots
    list_resp = client.get("/api/snapshots", headers=auth_headers)
    assert list_resp.status_code == 200
    snapshots = list_resp.json()
    assert len(snapshots) >= 2

    # 5. Get Snapshot Details
    detail_resp = client.get(f"/api/snapshots/{base_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    assert len(detail_resp.json()["assets"]) > 0

    # 6. Compute Snapshot Diff
    diff_resp = client.post(
        "/api/diffs",
        json={"base_snapshot_id": base_id, "target_snapshot_id": target_id},
        headers=auth_headers,
    )
    assert diff_resp.status_code == 201
    diff_data = diff_resp.json()
    diff_id = diff_data["id"]
    assert diff_data["exposure_summary"]["exposure_escalated"] > 0
    assert len(diff_data["owner_grouping"]) > 0

    # 7. Retrieve Diff Details
    get_diff_resp = client.get(f"/api/diffs/{diff_id}", headers=auth_headers)
    assert get_diff_resp.status_code == 200
    assert get_diff_resp.json()["id"] == diff_id

    # 8. Run ML Severity & Anomaly Evaluation
    ml_resp = client.post(
        "/api/ml/evaluate",
        json={"diff_id": diff_id, "anomaly_threshold": 0.5},
        headers=auth_headers,
    )
    assert ml_resp.status_code == 200
    ml_data = ml_resp.json()
    assert ml_data["total_evaluated"] > 0
    assert ml_data["critical_risk_count"] > 0
    assert len(ml_data["evaluations"]) > 0
    assert ml_data["benchmark_metrics"]["accuracy"] > 0.7

    # 9. Get ML Benchmark
    bench_resp = client.get("/api/ml/benchmark", headers=auth_headers)
    assert bench_resp.status_code == 200
    assert bench_resp.json()["model_metrics"]["total_samples"] == 32

    # 10. Generate LLM Remediation Advisory (offline fallback)
    adv_resp = client.post(
        "/api/advisory/generate",
        json={"diff_id": diff_id, "provider": "openai-compatible"},
        headers=auth_headers,
    )
    assert adv_resp.status_code == 200
    adv_data = adv_resp.json()
    assert adv_data["grounding_verified"] is True
    assert adv_data["grounded_resource_count"] > 0
    assert len(adv_data["prioritized_remediations"]) > 0

    # 11. Inspect Audit Logs
    audit_resp = client.get("/api/audit", headers=auth_headers)
    assert audit_resp.status_code == 200
    audit_entries = audit_resp.json()
    assert len(audit_entries) >= 4
    actions = {a["action"] for a in audit_entries}
    assert "COMPUTE_DIFF" in actions
    assert "RUN_ML_EVALUATION" in actions

    # 12. Admin deletion
    admin_token_resp = client.post("/api/auth/demo-token", json={"role": "admin", "username": "superadmin"})
    admin_token = admin_token_resp.json()["access_token"]
    del_resp = client.delete(f"/api/snapshots/{target_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert del_resp.status_code == 204
