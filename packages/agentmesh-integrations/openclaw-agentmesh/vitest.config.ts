// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const sdkRoot = fileURLToPath(
  new URL("../../agent-mesh/sdks/typescript/src/", import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: {
      "@microsoft/agentmesh-sdk/audit": `${sdkRoot}audit.ts`,
      "@microsoft/agentmesh-sdk/mcp": `${sdkRoot}mcp.ts`,
      "@microsoft/agentmesh-sdk/policy": `${sdkRoot}policy.ts`,
      "@microsoft/agentmesh-sdk/types": `${sdkRoot}types.ts`,
    },
  },
});
