// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@microsoft/agentmesh-sdk": fileURLToPath(
        new URL("./src/agentmesh-sdk-local.ts", import.meta.url),
      ),
      "openclaw/plugin-sdk/plugin-entry": fileURLToPath(
        new URL("./tests/openclaw-plugin-entry.stub.ts", import.meta.url),
      ),
    },
  },
});
