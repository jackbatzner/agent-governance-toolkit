// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
declare module "openclaw/plugin-sdk/plugin-entry" {
  export function definePluginEntry(options: {
    id: string;
    name: string;
    description: string;
    kind?: string;
    configSchema?: unknown;
    register: (api: any) => void;
  }): any;
}
