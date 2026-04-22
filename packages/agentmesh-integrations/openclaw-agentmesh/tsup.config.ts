// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  external: [
    "@microsoft/agentmesh-sdk",
    "@microsoft/agentmesh-sdk/audit",
    "@microsoft/agentmesh-sdk/mcp",
    "@microsoft/agentmesh-sdk/policy",
    "@microsoft/agentmesh-sdk/types",
  ],
});
