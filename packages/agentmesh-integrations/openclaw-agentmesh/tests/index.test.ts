// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, expect, it } from "vitest";
import { McpThreatType } from "@microsoft/agentmesh-sdk";
import {
  createOpenClawGovernanceAdapter,
  mapPolicyDecisionToOpenClawDecision,
  OpenClawGovernanceConfigError,
  OpenClawGovernanceError,
  type OpenClawAuditLogger,
  type OpenClawMcpScanner,
  type OpenClawPolicyEngine,
} from "../src";

describe("mapPolicyDecisionToOpenClawDecision", () => {
  it("maps require_approval to review", () => {
    expect(
      mapPolicyDecisionToOpenClawDecision({
        allowed: false,
        action: "require_approval",
        approvers: ["alice@contoso.com"],
        rateLimited: false,
        evaluatedAt: new Date(),
      }),
    ).toBe("review");
  });

  it("maps warn to review", () => {
    expect(
      mapPolicyDecisionToOpenClawDecision({
        allowed: false,
        action: "warn",
        approvers: [],
        rateLimited: false,
        evaluatedAt: new Date(),
      }),
    ).toBe("review");
  });
});

describe("createOpenClawGovernanceAdapter", () => {
  it("requires policy input", () => {
    expect(() => createOpenClawGovernanceAdapter({})).toThrow(
      OpenClawGovernanceConfigError,
    );
  });

  it("returns allow results and writes audit entries", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      agentId: "bot-1",
      policies: [
        {
          name: "allow-search",
          agents: ["*"],
          rules: [
            {
              name: "allow-search",
              condition: "tool.name == 'search'",
              ruleAction: "allow",
              description: "Search is allowed",
            },
          ],
          default_action: "deny",
        },
      ],
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "search",
      params: { query: "agent governance" },
    });

    expect(result.decision).toBe("allow");
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("Search is allowed");
    expect(result.auditEntry?.action).toBe("before_tool_call:search");
  });

  it("maps require_approval to review and preserves approvers", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      policies: [
        {
          name: "approval-policy",
          agents: ["*"],
          rules: [
            {
              name: "human-review",
              condition: "tool.name == 'shell'",
              ruleAction: "require_approval",
              approvers: ["alice@contoso.com"],
            },
          ],
          default_action: "deny",
        },
      ],
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "shell",
      params: { command: "whoami" },
    });

    expect(result.decision).toBe("review");
    expect(result.allowed).toBe(false);
    expect(result.approvers).toEqual(["alice@contoso.com"]);
  });

  it("propagates rewritten params for allowed calls", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      policies: [
        {
          name: "allow-read",
          agents: ["*"],
          rules: [
            {
              name: "allow-read",
              condition: "tool.name == 'read_file'",
              ruleAction: "allow",
            },
          ],
          default_action: "deny",
        },
      ],
      rewriteParams: async (input) => ({
        ...input.params,
        path: "sanitized.txt",
      }),
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "read_file",
      params: { path: "secret.txt" },
    });

    expect(result.decision).toBe("allow");
    expect(result.rewrittenParams).toEqual({ path: "sanitized.txt" });
  });

  it("fails closed when audit logging throws", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      policies: [
        {
          name: "allow-read",
          agents: ["*"],
          rules: [
            {
              name: "allow-read",
              condition: "tool.name == 'read_file'",
              ruleAction: "allow",
            },
          ],
          default_action: "deny",
        },
      ],
      audit: {
        logger: {
          log() {
            throw new Error("sink offline");
          },
        } satisfies OpenClawAuditLogger,
      },
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "read_file",
      params: { path: "file.txt" },
    });

    expect(result.decision).toBe("deny");
    expect(result.source).toBe("audit_error");
    expect(result.reason).toContain("sink offline");
  });

  it("throws when failClosed is disabled and evaluation fails", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      policyEngine: {
        evaluatePolicy() {
          throw new Error("bad rule");
        },
      } satisfies OpenClawPolicyEngine,
      failClosed: false,
    });

    await expect(
      adapter.evaluateBeforeToolCall({
        toolName: "search",
        params: { query: "x" },
      }),
    ).rejects.toThrow(OpenClawGovernanceError);
  });

  it("records after-call completion", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      policies: [
        {
          name: "allow-search",
          agents: ["*"],
          rules: [{ name: "allow-search", ruleAction: "allow" }],
        },
      ],
    });

    const result = await adapter.recordAfterToolCall({
      toolName: "search",
      result: { ok: true },
    });

    expect(result.action).toBe("complete");
    expect(result.decision).toBe("allow");
    expect(result.auditEntry.action).toBe("after_tool_call:search:complete");
  });

  it("maps MCP findings to review", () => {
    const adapter = createOpenClawGovernanceAdapter({
      policies: [
        {
          name: "allow-all",
          agents: ["*"],
          rules: [{ name: "allow-all", ruleAction: "allow" }],
        },
      ],
      mcpScanner: {
        scan() {
          return {
            tool_name: "search",
            threats: [
              {
                type: McpThreatType.ToolPoisoning,
                severity: "medium",
                description: "Injected text",
              },
            ],
            risk_score: 25,
            safe: false,
          };
        },
      } satisfies OpenClawMcpScanner,
    });

    const result = adapter.scanMcpToolDefinition({
      name: "search",
      description: "Search the web",
    });

    expect(result.recommendedDecision).toBe("review");
    expect(result.findings).toHaveLength(1);
  });
});
