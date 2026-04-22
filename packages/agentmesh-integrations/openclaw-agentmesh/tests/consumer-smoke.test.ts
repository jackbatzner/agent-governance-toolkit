// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, expect, it } from "vitest";
import { createOpenClawGovernanceAdapter } from "../src";

describe("consumer smoke flow", () => {
  it("supports before-call and after-call usage with the same adapter instance", async () => {
    const adapter = createOpenClawGovernanceAdapter({
      agentId: "openclaw-main-agent",
      policies: [
        {
          name: "tool-policy",
          agents: ["*"],
          rules: [
            {
              name: "allow-read-file",
              condition: "tool.name == 'read_file'",
              ruleAction: "allow",
            },
          ],
          default_action: "deny",
        },
      ],
    });

    const before = await adapter.evaluateBeforeToolCall({
      toolName: "read_file",
      params: { path: "README.md" },
      requestId: "req-123",
      sessionId: "session-123",
    });

    expect(before.decision).toBe("allow");
    expect(before.auditEntry?.agentId).toBe("openclaw-main-agent");

    const after = await adapter.recordAfterToolCall({
      toolName: "read_file",
      params: before.rewrittenParams ?? { path: "README.md" },
      result: "file contents",
      requestId: "req-123",
      sessionId: "session-123",
    });

    expect(after.action).toBe("complete");
    expect(after.auditEntry.action).toBe("after_tool_call:read_file:complete");
  });
});
