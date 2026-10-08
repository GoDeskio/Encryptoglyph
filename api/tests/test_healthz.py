import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("BUILD_SHA", "0123456789abcdef")
    return TestClient(app)


def test_healthz_returns_status_and_build_only(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "build": "0123456789ab"}


def test_docs_redoc_and_openapi_are_not_served(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        response = client.get(path)
        assert response.status_code == 404, path
