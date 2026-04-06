// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from './credential-redactor';
import {
  CredentialRedactorConfig,
  MCPFindingSeverity,
  MCPResponseFinding,
  MCPResponseScanResult,
  MCPResponseScannerConfig,
} from './types';
import { isRecord, truncatePreview } from './mcp-utils';

const INJECTION_TAG_PATTERNS = [
  /<\s*(?:system|assistant|instructions?|prompt)[^>]*>/gi,
  /<\|(?:system|assistant|user)\|>/gi,
  /\[\/?INST\]/g,
];

const IMPERATIVE_PATTERNS = [
  /ignore\s+(?:all\s+)?previous/gi,
  /override\s+(?:the\s+)?(?:previous|above|original)/gi,
  /do\s+not\s+follow/gi,
  /reveal\s+(?:all\s+)?(?:secrets|credentials|tokens)/gi,
  /include\s+the\s+contents?\s+of/gi,
];

const EXFILTRATION_PATTERNS = [
  /\b(?:curl|wget)\b/gi,
  /\b(?:send|upload|post|exfiltrat\w*)\b.{0,40}https?:\/\/[^\s"'<>]+/gi,
  /https?:\/\/(?:[^/\s]+\.)?(?:webhook|requestbin|ngrok|pastebin)[^\s"'<>]*/gi,
];

export class MCPResponseScanner {
  private readonly blockSeverities: Set<MCPFindingSeverity>;
  private readonly sanitizeText: boolean;
  private readonly redactor: CredentialRedactor;

  constructor(
    config: MCPResponseScannerConfig = {},
    redactorConfig: CredentialRedactorConfig = {},
  ) {
    this.blockSeverities = new Set(config.blockSeverities ?? ['critical']);
    this.sanitizeText = config.sanitizeText ?? true;
    this.redactor = new CredentialRedactor(redactorConfig);
  }

  scan<T>(value: T): MCPResponseScanResult<T> {
    const redactionResult = this.redactor.redact(value);
    const findings: MCPResponseFinding[] = redactionResult.redactions.map(
      (redaction) => ({
        type: 'credential_leak',
        severity: 'critical',
        message: `Credential-like value detected at ${redaction.path ?? '$'}`,
        matchedText: redaction.matchedText,
        path: redaction.path,
      }),
    );

    const sanitized = this.scanNode(
      redactionResult.redacted,
      '$',
      findings,
    ) as T;
    const blocked = findings.some((finding) =>
      this.blockSeverities.has(finding.severity),
    );

    return {
      safe: findings.length === 0,
      blocked,
      findings,
      original: value,
      sanitized,
    };
  }

  private scanNode(
    value: unknown,
    path: string,
    findings: MCPResponseFinding[],
  ): unknown {
    if (typeof value === 'string') {
      return this.scanString(value, path, findings);
    }

    if (Array.isArray(value)) {
      return value.map((item, index) =>
        this.scanNode(item, `${path}[${index}]`, findings),
      );
    }

    if (!isRecord(value)) {
      return value;
    }

    const clone: Record<string, unknown> = {};
    for (const [key, current] of Object.entries(value)) {
      clone[key] = this.scanNode(current, `${path}.${key}`, findings);
    }
    return clone;
  }

  private scanString(
    value: string,
    path: string,
    findings: MCPResponseFinding[],
  ): string {
    let sanitized = value;

    const detectors: Array<{
      type: MCPResponseFinding['type'];
      severity: MCPFindingSeverity;
      message: string;
      patterns: RegExp[];
    }> = [
      {
        type: 'instruction_injection',
        severity: 'critical',
        message: 'Instruction-like tag detected in tool output',
        patterns: INJECTION_TAG_PATTERNS,
      },
      {
        type: 'imperative_language',
        severity: 'warning',
        message: 'Imperative prompt-like text detected in tool output',
        patterns: IMPERATIVE_PATTERNS,
      },
      {
        type: 'exfiltration_url',
        severity: 'critical',
        message: 'Exfiltration-like URL or command detected in tool output',
        patterns: EXFILTRATION_PATTERNS,
      },
    ];

    for (const detector of detectors) {
      for (const pattern of detector.patterns) {
        pattern.lastIndex = 0;
        const matches = [...sanitized.matchAll(pattern)];
        if (matches.length === 0) {
          continue;
        }

        for (const match of matches) {
          findings.push({
            type: detector.type,
            severity: detector.severity,
            message: detector.message,
            matchedText: truncatePreview(match[0]),
            path,
          });
        }

        if (this.sanitizeText) {
          sanitized = sanitized.replace(
            pattern,
            `[FILTERED:${detector.type}]`,
          );
        }
      }
    }

    return sanitized;
  }
}
