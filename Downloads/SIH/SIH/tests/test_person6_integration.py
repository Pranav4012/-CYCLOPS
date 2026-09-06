from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app


PCAP = Path(__file__).parents[1] / "reference-impl" / "pcaps" / "mixed.pcap"


def test_backend_contract_and_incidents():
    client = TestClient(app)
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/alerts?limit=2").json()["limit"] == 2
    incidents = client.get("/api/incidents?limit=200").json()
    assert incidents["total"] >= 1
    incident_id = incidents["items"][0]["incident_id"]
    explanation = client.get(f"/api/incidents/{incident_id}/explanation")
    assert explanation.status_code == 200
    assert explanation.json()["supporting_detectors"]


def test_pcap_upload_returns_background_job():
    client = TestClient(app)
    with PCAP.open("rb") as capture:
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("mixed.pcap", capture, "application/vnd.tcpdump.pcap")},
        )
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    assert client.get(f"/api/jobs/{job_id}").status_code == 200


def test_websocket_event_contract():
    client = TestClient(app)
    with client.websocket_connect("/api/live") as socket:
        ready = socket.receive_json()
        assert ready["event"] == "READY"
        socket.send_text("ping")
        health = socket.receive_json()
        assert health["event"] == "HEALTH"
