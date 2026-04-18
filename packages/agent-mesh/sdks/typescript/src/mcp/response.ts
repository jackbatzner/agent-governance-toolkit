// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from './redactor';
import type { CredentialKind } from './redactor';

// ── Types ──

/** Threat categories for MCP response scanning. */
export enum McpResponseThreatType {
  PromptInjectionTag = 'prompt_injection_tag',
  ImperativePhrasing = 'imperative_phrasing',
  CredentialLeakage = 'credential_leakage',
  ExfiltrationUrl = 'exfiltration_url',
  DataBearingUrl = 'data_bearing_url',
}

/** A finding from response scanning. */
export interface McpResponseFinding {
  threat_type: McpResponseThreatType;
  labels: string[];
}

/** Result of scanning and sanitizing a response. */
export interface McpSanitizedResponse {
  sanitized: string;
  findings: McpResponseFinding[];
  modified: boolean;
}

// ── Patterns ──

const PROMPT_TAG_PATTERN = /(?:<!--[\s\S]*?-->|<system>[\s\S]*?<\/system>|<assistant>[\s\S]*?<\/assistant>)/gi;

const IMPERATIVE_PATTERN = /(?:ignore\s+(?:all\s+)?previous|you\s+must|reveal\s+(?:all\s+)?secrets|override\s+(?:the\s+)?instructions?)/gi;

const URL_PATTERN = /https?:\/\/[^\s"']+/g;

/** URLs with embedded data (query params containing base64, hex, or long encoded values). */
const DATA_BEARING_URL_PATTERN = /https?:\/\/[^\s"']*[?&][^\s"']*(?:[A-Za-z0-9+/=]{20,}|[0-9a-fA-F]{20,}|%[0-9A-Fa-f]{2}.*%[0-9A-Fa-f]{2})/g;

// ── McpResponseScanner ──

/**
 * Scans MCP tool responses for prompt injection, credential leakage,
 * and data exfiltration patterns.
 */
export class McpResponseScanner {
  private readonly redactor: CredentialRedactor;

  constructor(redactor?: CredentialRedactor) {
    this.redactor = redactor ?? new CredentialRedactor();
  }

  /** Scan and sanitize response text. Returns findings and cleaned output. */
  scanText(text: string): McpSanitizedResponse {
    const findings: McpResponseFinding[] = [];
    let sanitized = text;

    // Prompt injection tags
    const tagMatches = text.match(PROMPT_TAG_PATTERN);
    if (tagMatches) {
      findings.push({
        threat_type: McpResponseThreatType.PromptInjectionTag,
        labels: tagMatches,
      });
      sanitized = sanitized.replace(PROMPT_TAG_PATTERN, '');
    }

    // Imperative phrasing
    const imperativeMatches = text.match(IMPERATIVE_PATTERN);
    if (imperativeMatches) {
      findings.push({
        threat_type: McpResponseThreatType.ImperativePhrasing,
        labels: imperativeMatches,
      });
    }

    // Credential leakage
    const redactionResult = this.redactor.redact(sanitized);
    if (redactionResult.modified) {
      findings.push({
        threat_type: McpResponseThreatType.CredentialLeakage,
        labels: redactionResult.detected.map((k) => k as string),
      });
      sanitized = redactionResult.sanitized;
    }

    // Exfiltration URLs — classify severity by data content
    const dataBearingMatches: string[] = sanitized.match(DATA_BEARING_URL_PATTERN) ?? [];
    const allUrlMatches: string[] = sanitized.match(URL_PATTERN) ?? [];
    if (dataBearingMatches.length > 0) {
      findings.push({
        threat_type: McpResponseThreatType.DataBearingUrl,
        labels: dataBearingMatches,
      });
    }
    const plainUrls = allUrlMatches.filter((u) => !dataBearingMatches.includes(u));
    if (plainUrls.length > 0) {
      findings.push({
        threat_type: McpResponseThreatType.ExfiltrationUrl,
        labels: plainUrls,
      });
    }

    return {
      sanitized,
      findings,
      modified: sanitized !== text,
    };
  }
}
