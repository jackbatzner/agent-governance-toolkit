// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, expect, it, vi } from "vitest";
import pluginEntry from "../src/plugin-entry";
import {
  createOpenClawGovernanceAdapterFromPluginConfig,
  type OpenClawPluginApi,
} from "../src";

describe("native OpenClaw plugin entry", () => {
  it("exposes a real plugin entry definition", () => {
    expect(pluginEntry.id).toBe("agentmesh-openclaw");
    expect(pluginEntry.name).toContain("AgentMesh");
    expect(typeof pluginEntry.register).toBe("function");
  });

  it("loads policies from plugin config", async () => {
    const adapter = createOpenClawGovernanceAdapterFromPluginConfig({
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
    });

    const result = await adapter.evaluateBeforeToolCall({
      toolName: "read_file",
      params: { path: "README.md" },
    });

    expect(result.decision).toBe("allow");
  });

  it("registers before and after tool hooks from plugin config", async () => {
    const registrations: Array<{
      hook: string | string[];
      handler: (event: unknown) => Promise<unknown> | unknown;
    }> = [];
    const logger = {
      info: vi.fn(),
      error: vi.fn(),
    };

    const api: OpenClawPluginApi = {
      id: "agentmesh-openclaw",
      name: "AgentMesh OpenClaw Governance",
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
      },
      logger,
      registerHook(hook, handler) {
        registrations.push({ hook, handler });
      },
    };

    pluginEntry.register(api);

    expect(registrations).toHaveLength(2);

    const beforeHook = registrations.find((registration) => registration.hook === "before_tool_call");
    expect(beforeHook).toBeDefined();

    const beforeResult = await beforeHook!.handler({
      toolName: "shell",
      params: { command: "whoami" },
      toolCallId: "call-1",
      sessionKey: "session-1",
      agentId: "agent-1",
    });

    expect(beforeResult).toEqual({
      requireApproval: true,
      blockReason: expect.stringContaining("Suggested approvers: ops@contoso.com"),
    });

    const afterHook = registrations.find((registration) => registration.hook === "after_tool_call");
    expect(afterHook).toBeDefined();

    await afterHook!.handler({
      toolName: "shell",
      params: { command: "whoami" },
      sessionKey: "session-1",
      result: "jack",
    });

    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledOnce();
  });
});
