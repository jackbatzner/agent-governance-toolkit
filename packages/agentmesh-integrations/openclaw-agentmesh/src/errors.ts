// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export class OpenClawGovernanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenClawGovernanceError";
  }
}

export class OpenClawGovernanceConfigError extends OpenClawGovernanceError {
  constructor(message: string) {
    super(message);
    this.name = "OpenClawGovernanceConfigError";
  }
}

export class OpenClawGovernanceAuditError extends OpenClawGovernanceError {
  constructor(message: string) {
    super(message);
    this.name = "OpenClawGovernanceAuditError";
  }
}
