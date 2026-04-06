# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the MCP FastAPI governance demo."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient

EXAMPLE_DIR = Path(__file__).parent
PACKAGE_ROOT = EXAMPLE_DIR.parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))
sys.path.insert(0, str(EXAMPLE_DIR))

create_app = importlib.import_module("server").create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _session_token(client: TestClient, agent_id: str = "demo-agent") -> str:
    response = client.post("/session", json={"agent_id": agent_id, "user_id": "demo-user"})
    assert response.status_code == 200
    return response.json()["session_token"]


def test_health_reports_governance_status() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_call_tool_allows_safe_search() -> None:
    client = _client()
    token = _session_token(client)
    response = client.post(
        "/call-tool",
        headers={"X-Session-Token": token},
        json={
            "agent_id": "demo-agent",
            "tool_name": "search_docs",
            "params": {"query": "OWASP MCP hardening"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["signed_message"]["verified"] is True
    assert body["response_scan"]["is_safe"] is True


def test_call_tool_blocks_sensitive_response() -> None:
    client = _client()
    token = _session_token(client)
    response = client.post(
        "/call-tool",
        headers={"X-Session-Token": token},
        json={
            "agent_id": "demo-agent",
            "tool_name": "export_customer_profile",
            "params": {
                "customer_id": "cust-007",
                "approval_ticket": "demo-approved",
            },
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "credential_leak" in str(detail["response_scan"]["threats"])
    assert "[REDACTED]" in detail["redacted_output"]
