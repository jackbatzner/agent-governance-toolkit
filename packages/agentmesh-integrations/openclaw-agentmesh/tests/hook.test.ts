// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, expect, it } from "vitest";
import {
  applyBeforeToolCallResultToHookEvent,
  type OpenClawAfterToolCallResult,
  createOpenClawAfterToolCallInputFromHookEvent,
  createOpenClawBeforeToolCallInputFromHookEvent,
  createOpenClawGovernanceAdapterFromConfig,
  createOpenClawHookEventHandler,
  type OpenClawInternalHookEvent,
} from "../src";

describe("OpenClaw internal hook helpers", () => {
  it("maps a before-tool hook event into adapter input", () => {
    const input = createOpenClawBeforeToolCallInputFromHookEvent({
      type: "tool",
      action: "before_tool_call",
      sessionKey: "session-1",
      timestamp: new Date("2026-01-01T00:00:00Z"),
      messages: [],
      context: {
        toolName: "shell",
        params: {
          command: "whoami",
        },
        agentId: "agent-1",
      },
    });

    expect(input).toEqual({
      toolName: "shell",
      params: { command: "whoami" },
      requestId: undefined,
      sessionId: "session-1",
      userId: undefined,
      agentId: "agent-1",
      agentDid: undefined,
      toolDescription: undefined,
      metadata: {
        hookType: "tool",
        hookAction: "before_tool_call",
        hookTimestamp: "2026-01-01T00:00:00.000Z",
      },
      runtimeContext: {
        toolName: "shell",
        params: {
          command: "whoami",
        },
        agentId: "agent-1",
      },
    });
  });

  it("applies deny decisions back onto the mutable hook event", () => {
    const event: OpenClawInternalHookEvent = {
      type: "tool",
      action: "before_tool_call",
      sessionKey: "session-1",
      timestamp: new Date("2026-01-01T00:00:00Z"),
      messages: [],
      context: {
        toolName: "write_file",
        params: {
          path: "/secrets/production.txt",
        },
      },
    };

    applyBeforeToolCallResultToHookEvent(event, {
      decision: "deny",
      allowed: false,
      approvers: [],
      reason: "Blocked by AGT policy.",
      source: "policy",
    });

    expect(event.context.block).toBe(true);
    expect(event.context.blockReason).toBe("Blocked by AGT policy.");
    expect(event.messages).toContain("Blocked by AGT policy.");
  });

  it("handles before and after hook events with the same adapter", async () => {
    const handler = createOpenClawHookEventHandler(
      createOpenClawGovernanceAdapterFromConfig({
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
      }),
    );

    const beforeEvent: OpenClawInternalHookEvent = {
      type: "tool",
      action: "before_tool_call",
      sessionKey: "session-1",
      timestamp: new Date("2026-01-01T00:00:00Z"),
      messages: [],
      context: {
        toolName: "read_file",
        params: {
          path: "README.md",
        },
      },
    };

    const beforeResult = await handler(beforeEvent);
    expect(beforeResult?.kind).toBe("before_tool_call");
    if (!beforeResult || beforeResult.kind !== "before_tool_call") {
      throw new Error("expected a before-tool-call result");
    }
    expect(beforeResult.governanceResult.decision).toBe("allow");

    const afterEvent: OpenClawInternalHookEvent = {
      type: "tool",
      action: "after_tool_call",
      sessionKey: "session-1",
      timestamp: new Date("2026-01-01T00:00:05Z"),
      messages: [],
      context: {
        toolName: "read_file",
        params: {
          path: "README.md",
        },
        result: "file contents",
      },
    };

    const afterInput = createOpenClawAfterToolCallInputFromHookEvent(afterEvent);
    expect(afterInput?.toolName).toBe("read_file");

    const afterResult = await handler(afterEvent);
    expect(afterResult?.kind).toBe("after_tool_call");
    if (!afterResult || afterResult.kind !== "after_tool_call") {
      throw new Error("expected an after-tool-call result");
    }
    expect((afterResult.governanceResult as OpenClawAfterToolCallResult).action).toBe("complete");
  });
});
