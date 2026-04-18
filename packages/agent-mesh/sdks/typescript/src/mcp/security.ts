// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'node:crypto';
import type { McpAuditSink } from './stores';
import type { Clock } from './clock';
import { SystemClock } from './clock';

// ── Enums ──

/** Threat categories recognised by the scanner. */
export enum McpThreatType {
  ToolPoisoning = 'tool_poisoning',
  Typosquatting = 'typosquatting',
  HiddenInstruction = 'hidden_instruction',
  RugPull = 'rug_pull',
  SchemaAbuse = 'schema_abuse',
  CrossServerAttack = 'cross_server_attack',
  DescriptionInjection = 'description_injection',
}

/** Severity levels for detected threats. */
export enum McpSeverity {
  Info = 'info',
  Warning = 'warning',
  Critical = 'critical',
}

// ── Types ──

/** A single threat detected during a scan. */
export interface McpThreat {
  type: McpThreatType;
  severity: McpSeverity;
  tool_name: string;
  server_name: string;
  message: string;
  details?: string;
}

/** Result of scanning one or more MCP tool definitions. */
export interface McpScanResult {
  tool_name: string;
  threats: McpThreat[];
  risk_score: number;
  safe: boolean;
}

/** Minimal MCP tool definition accepted by the scanner. */
export interface McpToolDefinition {
  name: string;
  description: string;
  input_schema?: string;
  server_name?: string;
}

/** Fingerprint of a tool for rug-pull detection. */
export interface McpToolFingerprint {
  tool_name: string;
  server_name: string;
  description_hash: string;
  schema_hash: string;
  first_seen: number;
  last_seen: number;
  version: number;
}

// ── Constants ──

const KNOWN_TOOL_NAMES: string[] = [
  'read_file', 'write_file', 'execute_command', 'search', 'browse',
  'fetch', 'list_directory', 'create_file', 'delete_file', 'run_script',
  'get_weather', 'send_email', 'query_database', 'http_request', 'calculator',
];

const POISONING_PATTERNS: RegExp[] = [
  /<system>/i, /ignore previous/i, /you must/i, /disregard/i,
  /override/i, /forget (all|your|previous)/i, /new instructions/i, /act as/i,
];

const ZERO_WIDTH_CHARS = [
  '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E',
];

const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
  '\u0458': 'j', '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p',
};

const INSTRUCTION_PATTERNS: RegExp[] = [
  /you (should|must|need to)/i, /always /i, /never /i, /do not /i,
  /important:/i, /warning:/i, /note:/i, /step \d/i, /first,/i, /finally,/i,
];

const DESCRIPTION_INJECTION_PATTERNS: RegExp[] = [
  /\bwhen\b.+\bcall\b/i, /\binstead\b.+\buse\b/i,
  /\bbefore\b.+\brun\b/i, /\bafter\b.+\bexecute\b/i,
  /\bfirst\b.+\bthen\b/i,
];

const SUSPICIOUS_SCHEMA_FIELDS = [
  '__proto__', 'constructor', 'prototype', 'eval', 'exec',
  'system', 'command', 'shell', 'script',
];

const RUG_PULL_DESCRIPTION_LENGTH = 500;
const RUG_PULL_MIN_INSTRUCTION_MATCHES = 2;
const MAX_REASONABLE_SCHEMA_LENGTH = 10_000;

const SEVERITY_WEIGHT: Record<McpSeverity, number> = {
  [McpSeverity.Info]: 10,
  [McpSeverity.Warning]: 25,
  [McpSeverity.Critical]: 80,
};

// ── Helpers ──

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0) as number[]);
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

// ── McpSecurityScanner ──

export class McpSecurityScanner {
  private readonly fingerprints = new Map<string, McpToolFingerprint>();
  private readonly auditSink?: McpAuditSink;
  private readonly clock: Clock;

  constructor(options?: { auditSink?: McpAuditSink; clock?: Clock }) {
    this.auditSink = options?.auditSink;
    this.clock = options?.clock ?? new SystemClock();
  }

  /** Scan a single tool definition for all threat types. */
  scan(tool: McpToolDefinition): McpScanResult {
    const serverName = tool.server_name ?? 'default';
    const threats: McpThreat[] = [];

    this.detectToolPoisoning(tool, serverName, threats);
    this.detectTyposquatting(tool, serverName, threats);
    this.detectHiddenInstructions(tool, serverName, threats);
    this.detectRugPull(tool, serverName, threats);
    this.detectSchemaAbuse(tool, serverName, threats);
    this.detectCrossServerAttack(tool, serverName, threats);
    this.detectDescriptionInjection(tool, serverName, threats);

    const riskScore = Math.min(
      100,
      threats.reduce((sum, t) => sum + SEVERITY_WEIGHT[t.severity], 0),
    );

    const result: McpScanResult = {
      tool_name: tool.name,
      threats,
      risk_score: riskScore,
      safe: threats.length === 0,
    };

    this.auditSink?.record({
      timestamp: this.clock.now(),
      agent_id: 'scanner',
      action: 'mcp_tool_scan',
      decision: result.safe ? 'safe' : 'threats_detected',
      details: { tool_name: tool.name, server_name: serverName, threatCount: threats.length },
    });

    return result;
  }

  /** Scan multiple tool definitions. */
  scanAll(tools: McpToolDefinition[]): McpScanResult[] {
    return tools.map((t) => this.scan(t));
  }

  /** Register a tool fingerprint for rug-pull detection. */
  registerTool(tool: McpToolDefinition): McpToolFingerprint {
    const serverName = tool.server_name ?? 'default';
    const key = `${serverName}:${tool.name}`;
    const now = this.clock.now();
    const descHash = sha256(tool.description);
    const schemaHash = sha256(tool.input_schema ?? '');

    const existing = this.fingerprints.get(key);
    if (existing) {
      existing.last_seen = now;
      if (existing.description_hash !== descHash || existing.schema_hash !== schemaHash) {
        existing.description_hash = descHash;
        existing.schema_hash = schemaHash;
        existing.version++;
      }
      return { ...existing };
    }

    const fp: McpToolFingerprint = {
      tool_name: tool.name,
      server_name: serverName,
      description_hash: descHash,
      schema_hash: schemaHash,
      first_seen: now,
      last_seen: now,
      version: 1,
    };
    this.fingerprints.set(key, fp);
    return { ...fp };
  }

  /** Check if a tool's definition has changed since it was registered (rug-pull). */
  checkRugPull(tool: McpToolDefinition): McpThreat | null {
    const serverName = tool.server_name ?? 'default';
    const key = `${serverName}:${tool.name}`;
    const existing = this.fingerprints.get(key);
    if (!existing) return null;

    const descHash = sha256(tool.description);
    const schemaHash = sha256(tool.input_schema ?? '');

    if (existing.description_hash !== descHash || existing.schema_hash !== schemaHash) {
      return {
        type: McpThreatType.RugPull,
        severity: McpSeverity.Critical,
        tool_name: tool.name,
        server_name: serverName,
        message: `Tool "${tool.name}" definition changed since registration (version ${existing.version})`,
        details: `desc_changed=${existing.description_hash !== descHash}, schema_changed=${existing.schema_hash !== schemaHash}`,
      };
    }
    return null;
  }

  // ── Private detectors ──

  private detectToolPoisoning(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    // Scan tool description
    for (const pattern of POISONING_PATTERNS) {
      const match = pattern.exec(tool.description);
      if (match) {
        threats.push({
          type: McpThreatType.ToolPoisoning,
          severity: McpSeverity.Critical,
          tool_name: tool.name,
          server_name: serverName,
          message: `Prompt-injection pattern in tool description: "${match[0]}"`,
          details: match[0],
        });
      }
    }

    // Scan inputSchema content for embedded prompt injection
    if (tool.input_schema) {
      for (const pattern of POISONING_PATTERNS) {
        const match = pattern.exec(tool.input_schema);
        if (match) {
          threats.push({
            type: McpThreatType.ToolPoisoning,
            severity: McpSeverity.Critical,
            tool_name: tool.name,
            server_name: serverName,
            message: `Prompt-injection pattern in inputSchema: "${match[0]}"`,
            details: match[0],
          });
        }
      }
    }

    if (/%[0-9A-Fa-f]{2}/.test(tool.description)) {
      try {
        const decoded = decodeURIComponent(tool.description);
        for (const pattern of POISONING_PATTERNS) {
          const match = pattern.exec(decoded);
          if (match) {
            threats.push({
              type: McpThreatType.ToolPoisoning,
              severity: McpSeverity.Critical,
              tool_name: tool.name,
              server_name: serverName,
              message: `Encoded prompt-injection after URL-decoding: "${match[0]}"`,
              details: match[0],
            });
          }
        }
      } catch (_) {
        // decodeURIComponent throws on malformed percent-sequences (e.g. "%GG");
        // the tool description is still scanned by other detectors, so skipping
        // the decoded-form check here is safe.
      }
    }
  }

  private detectTyposquatting(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    const name = tool.name.toLowerCase();
    for (const known of KNOWN_TOOL_NAMES) {
      if (name === known) continue;
      const dist = levenshtein(name, known);
      if (dist > 0 && dist <= 2) {
        threats.push({
          type: McpThreatType.Typosquatting,
          severity: dist === 1 ? McpSeverity.Critical : McpSeverity.Warning,
          tool_name: tool.name,
          server_name: serverName,
          message: `"${tool.name}" is similar to known tool "${known}" (distance ${dist})`,
          details: known,
        });
      }
    }
  }

  private detectHiddenInstructions(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    for (const zwc of ZERO_WIDTH_CHARS) {
      if (tool.description.includes(zwc)) {
        threats.push({
          type: McpThreatType.HiddenInstruction,
          severity: McpSeverity.Critical,
          tool_name: tool.name,
          server_name: serverName,
          message: `Zero-width character U+${(zwc.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')} in description`,
          details: `U+${(zwc.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
        });
        break;
      }
    }

    for (const ch of tool.description) {
      if (HOMOGLYPH_MAP[ch]) {
        threats.push({
          type: McpThreatType.HiddenInstruction,
          severity: McpSeverity.Critical,
          tool_name: tool.name,
          server_name: serverName,
          message: `Homoglyph "${ch}" looks like "${HOMOGLYPH_MAP[ch]}"`,
          details: ch,
        });
        break;
      }
    }
  }

  private detectRugPull(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    if (tool.description.length <= RUG_PULL_DESCRIPTION_LENGTH) return;
    let matches = 0;
    for (const p of INSTRUCTION_PATTERNS) if (p.test(tool.description)) matches++;
    if (matches >= RUG_PULL_MIN_INSTRUCTION_MATCHES) {
      threats.push({
        type: McpThreatType.RugPull,
        severity: McpSeverity.Warning,
        tool_name: tool.name,
        server_name: serverName,
        message: `Long description (${tool.description.length} chars) with ${matches} instruction patterns`,
        details: `length=${tool.description.length}, patterns=${matches}`,
      });
    }
  }

  private detectSchemaAbuse(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    if (!tool.input_schema) return;

    if (tool.input_schema.length > MAX_REASONABLE_SCHEMA_LENGTH) {
      threats.push({
        type: McpThreatType.SchemaAbuse,
        severity: McpSeverity.Warning,
        tool_name: tool.name,
        server_name: serverName,
        message: `Oversized input schema (${tool.input_schema.length} chars)`,
        details: `length=${tool.input_schema.length}`,
      });
    }

    const lower = tool.input_schema.toLowerCase();
    for (const field of SUSPICIOUS_SCHEMA_FIELDS) {
      if (lower.includes(`"${field}"`)) {
        threats.push({
          type: McpThreatType.SchemaAbuse,
          severity: McpSeverity.Critical,
          tool_name: tool.name,
          server_name: serverName,
          message: `Suspicious field "${field}" in input schema`,
          details: field,
        });
      }
    }
  }

  private detectCrossServerAttack(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    const crossRefPattern = /\b(?:call|invoke|use|run)\b.+\b(?:server|service|endpoint)\b/i;
    if (crossRefPattern.test(tool.description)) {
      threats.push({
        type: McpThreatType.CrossServerAttack,
        severity: McpSeverity.Warning,
        tool_name: tool.name,
        server_name: serverName,
        message: 'Tool description references another server/service — possible cross-server attack vector',
      });
    }
  }

  private detectDescriptionInjection(tool: McpToolDefinition, serverName: string, threats: McpThreat[]): void {
    for (const pattern of DESCRIPTION_INJECTION_PATTERNS) {
      const match = pattern.exec(tool.description);
      if (match) {
        threats.push({
          type: McpThreatType.DescriptionInjection,
          severity: McpSeverity.Warning,
          tool_name: tool.name,
          server_name: serverName,
          message: `Instruction-like pattern in description: "${match[0]}"`,
          details: match[0],
        });
        break;
      }
    }
  }
}
