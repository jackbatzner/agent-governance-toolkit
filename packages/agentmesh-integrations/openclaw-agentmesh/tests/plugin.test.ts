// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import pluginEntry from "../src/plugin-entry";
import {
  createOpenClawGovernanceAdapterFromPluginConfig,
  registerOpenClawGovernanceHooks,
  type OpenClawNativePluginApi,
  type OpenClawNativePluginConfig,
} from "../src";

describe("native OpenClaw plugin entry", () => {
  it("exposes a native plugin entry definition", () => {
    expect(pluginEntry.id).toBe("agentmesh-openclaw");
    expect(pluginEntry.name).toContain("AgentMesh");
    expect(typeof pluginEntry.register).toBe("function");
  });

  it("loads policies from a configured JSON file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agt-openclaw-"));
    const policyPath = join(dir, "policies.json");
    writeFileSync(
      policyPath,
      JSON.stringify([
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
      ]),
      "utf8",
    );

    const adapter = createOpenClawGovernanceAdapterFromPluginConfig({
      policyFile: policyPath,
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "read_file",
      params: { path: "README.md" },
    });

    expect(result.decision).toBe("allow");
  });

  it("registers before and after hooks and maps review decisions to approvals", async () => {
    const registrations: Array<{
      events: string | string[];
      handler: (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
    }> = [];
    const logger = {
      info: vi.fn(),
      error: vi.fn(),
    };
    const api: OpenClawNativePluginApi = {
      pluginConfig: {
        policies: [
          {
            name: "approval-policy",
            agents: ["*"],
            rules: [
              {
                name: "review-shell",
                condition: "tool.name == 'shell'",
                ruleAction: "require_approval",
                approvers: ["ops@contoso.com"],
              },
            ],
            default_action: "deny",
          },
        ],
        audit: {
          enabled: true,
        },
      } satisfies OpenClawNativePluginConfig,
      logger,
      registerHook(events, handler) {
        registrations.push({ events, handler });
      },
    };

    registerOpenClawGovernanceHooks(api);

    expect(registrations).toHaveLength(2);

    const beforeHook = registrations.find((registration) => registration.events === "before_tool_call");
    expect(beforeHook).toBeDefined();

    const beforeResult = await beforeHook!.handler(
      {
        toolName: "shell",
        params: { command: "whoami" },
        toolCallId: "call-1",
      },
      {
        agentId: "agent-1",
        sessionId: "session-1",
        toolName: "shell",
        toolCallId: "call-1",
      },
    );

    expect(beforeResult).toEqual({
      requireApproval: {
        title: 'Approval required for tool "shell"',
        description: expect.stringContaining("Suggested approvers: ops@contoso.com"),
        severity: "warning",
        pluginId: "agentmesh-openclaw",
      },
    });

    const afterHook = registrations.find((registration) => registration.events === "after_tool_call");
    expect(afterHook).toBeDefined();

    await afterHook!.handler(
      {
        toolName: "shell",
        params: { command: "whoami" },
        toolCallId: "call-1",
        result: "jack",
        durationMs: 10,
      },
      {
        agentId: "agent-1",
        sessionId: "session-1",
        toolName: "shell",
        toolCallId: "call-1",
      },
    );

    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledOnce();
  });
});
