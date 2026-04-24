// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/plugin-entry.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  external: [
    "@microsoft/agentmesh-sdk",
    "openclaw/plugin-sdk/plugin-entry",
  ],
});
