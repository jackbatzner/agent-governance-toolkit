# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Minimal FastAPI server showing MCP governance primitives end to end."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from agent_os.credential_redactor import CredentialRedactor
from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.mcp_gateway import ApprovalStatus, MCPGateway
from agent_os.mcp_message_signer import MCPMessageSigner
from agent_os.mcp_response_scanner import MCPResponseScanner
from agent_os.mcp_session_auth import MCPSessionAuthenticator
from agent_os.mcp_sliding_rate_limiter import MCPSlidingRateLimiter

_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


class SessionRequest(BaseModel):
    agent_id: str
    user_id: str | None = None


class ToolCallRequest(BaseModel):
    agent_id: str
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)


class GovernanceDemo:
    def __init__(self) -> None:
        self.policy = GovernancePolicy(
            name="mcp-fastapi-demo",
            max_tool_calls=8,
            allowed_tools=["search_docs", "export_customer_profile"],
            blocked_patterns=[
                ("ignore\\s+all\\s+previous", PatternType.REGEX),
                ("password", PatternType.SUBSTRING),
            ],
            log_all_calls=True,
        )
        self.gateway = MCPGateway(
            self.policy,
            sensitive_tools=["export_customer_profile"],
            approval_callback=self._approve_sensitive_tool,
        )
        self.gateway_config = MCPGateway.wrap_mcp_server(
            {"name": "mcp-fastapi-demo", "transport": "http"},
            self.policy,
            sensitive_tools=["export_customer_profile"],
        )
        self.signer = MCPMessageSigner(MCPMessageSigner.generate_key())
        self.sessions = MCPSessionAuthenticator(
            session_ttl=timedelta(minutes=30),
            max_concurrent_sessions=25,
        )
        self.rate_limiter = MCPSlidingRateLimiter(max_calls_per_window=3, window_size=60.0)
        self.response_scanner = MCPResponseScanner()

    @staticmethod
    def _approve_sensitive_tool(
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> ApprovalStatus:
        del agent_id, tool_name
        return (
            ApprovalStatus.APPROVED
            if params.get("approval_ticket") == "demo-approved"
            else ApprovalStatus.DENIED
        )

    def issue_session(self, agent_id: str, user_id: str | None) -> str:
        return self.sessions.create_session(agent_id, user_id)

    def invoke(self, request: ToolCallRequest, session_token: str) -> dict[str, Any]:
        session = self.sessions.validate_session(request.agent_id, session_token)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid or expired MCP session token.")
        if not self.rate_limiter.try_acquire(session.rate_limit_key):
            raise HTTPException(status_code=429, detail="Sliding-window MCP rate limit exceeded.")

        payload = json.dumps(request.model_dump(), sort_keys=True)
        envelope = self.signer.sign_message(payload, sender_id=request.agent_id)
        verification = self.signer.verify_message(envelope)
        if not verification.is_valid:
            raise HTTPException(status_code=401, detail=verification.failure_reason)

        allowed, reason = self.gateway.intercept_tool_call(
            request.agent_id,
            request.tool_name,
            request.params,
        )
        if not allowed:
            status_code = 429 if "budget" in reason.casefold() else 403
            raise HTTPException(status_code=status_code, detail=reason)

        raw_output = self._run_tool(request.tool_name, request.params)
        response_scan = self.response_scanner.scan_response(raw_output, tool_name=request.tool_name)
        sanitized_output, stripped_threats = self.response_scanner.sanitize_response(
            raw_output,
            tool_name=request.tool_name,
        )
        redacted_output = self._redact_sensitive_output(sanitized_output)
        pii_findings = self._pii_findings(raw_output)
        if not response_scan.is_safe or pii_findings:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Tool response blocked by MCP governance.",
                    "response_scan": self._serialize_scan(response_scan),
                    "pii_findings": pii_findings,
                    "redacted_output": redacted_output,
                },
            )

        return {
            "status": "allowed",
            "reason": reason,
            "signed_message": {
                "verified": verification.is_valid,
                "nonce": envelope.nonce,
                "sender_id": envelope.sender_id,
                "timestamp": envelope.timestamp.isoformat(),
            },
            "session": {
                "agent_id": session.agent_id,
                "expires_at": session.expires_at.isoformat(),
            },
            "input_sanitizer": "MCPGateway built-in blocked-pattern and dangerous-pattern filters",
            "request_for_logs": CredentialRedactor.redact_data_structure(request.params),
            "response_scan": self._serialize_scan(response_scan),
            "response": redacted_output,
            "remaining_window_budget": self.rate_limiter.get_remaining_budget(
                session.rate_limit_key
            ),
            "gateway_call_count": self.gateway.get_agent_call_count(request.agent_id),
            "audit_entries": len(self.gateway.audit_log),
            "wrapped_server": asdict(self.gateway_config),
            "stripped_response_threats": [asdict(threat) for threat in stripped_threats],
        }

    @staticmethod
    def _run_tool(tool_name: str, params: dict[str, Any]) -> str:
        if tool_name == "search_docs":
            query = str(params.get("query", "mcp governance"))
            return f"Found MCP guidance for query '{query}'. No secrets detected."
        if tool_name == "export_customer_profile":
            customer_id = str(params.get("customer_id", "cust-001"))
            return (
                f"Customer {customer_id}: alice@example.com, SSN 123-45-6789, "
                "API key: sk-demo-secret-abcdefghijklmnopqrstuvwxyz"
            )
        raise HTTPException(status_code=404, detail=f"Unknown tool '{tool_name}'.")

    @staticmethod
    def _pii_findings(content: str) -> list[str]:
        findings: list[str] = []
        if _EMAIL_PATTERN.search(content):
            findings.append("email")
        if _SSN_PATTERN.search(content):
            findings.append("ssn")
        return findings

    @staticmethod
    def _redact_sensitive_output(content: str) -> str:
        redacted = CredentialRedactor.redact(content)
        redacted = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", redacted)
        return _SSN_PATTERN.sub("[REDACTED_SSN]", redacted)

    @staticmethod
    def _serialize_scan(scan: Any) -> dict[str, Any]:
        return {
            "is_safe": scan.is_safe,
            "tool_name": scan.tool_name,
            "threats": [asdict(threat) for threat in scan.threats],
        }


def create_app() -> FastAPI:
    demo = GovernanceDemo()
    app = FastAPI(title="Agent OS MCP FastAPI Demo", version="1.0.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "active_sessions": demo.sessions.active_session_count,
            "gateway_audit_entries": len(demo.gateway.audit_log),
            "allowed_tools": demo.gateway_config.allowed_tools,
            "sensitive_tools": demo.gateway_config.sensitive_tools,
            "rate_limit_window_seconds": demo.rate_limiter.window_size,
            "rate_limit_capacity": demo.rate_limiter.max_calls_per_window,
        }

    @app.post("/session")
    def create_session(request: SessionRequest) -> dict[str, Any]:
        token = demo.issue_session(request.agent_id, request.user_id)
        return {"session_token": token, "expires_in_seconds": 1800}

    @app.post("/call-tool")
    def call_tool(
        request: ToolCallRequest,
        x_session_token: str = Header(..., alias="X-Session-Token"),
    ) -> dict[str, Any]:
        return demo.invoke(request, x_session_token)

    return app


app = create_app()
