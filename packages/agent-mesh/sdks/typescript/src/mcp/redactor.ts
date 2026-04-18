// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/** Credential category. */
export enum CredentialKind {
  ApiKey = 'api_key',
  BearerToken = 'bearer_token',
  ConnectionString = 'connection_string',
  SecretAssignment = 'secret_assignment',
  OpenAiKey = 'openai_key',
  GitHubToken = 'github_token',
  AwsKey = 'aws_key',
  AzureConnectionString = 'azure_connection_string',
  PemKey = 'pem_key',
  JwtToken = 'jwt_token',
}

/** A single credential match. */
export interface CredentialMatch {
  kind: CredentialKind;
  /** Masked snippet (first 4 chars + '***'). Use `rawMatch` for unmasked value. */
  matched: string;
}

/** A single credential match with the raw (unmasked) matched text. */
export interface CredentialMatchRaw {
  kind: CredentialKind;
  matched: string;
}

/** Result of redacting credentials from a string. */
export interface RedactionResult {
  sanitized: string;
  detected: CredentialKind[];
  modified: boolean;
}

interface CredentialPattern {
  kind: CredentialKind;
  pattern: RegExp;
  placeholder: string;
}

const PATTERNS: CredentialPattern[] = [
  {
    kind: CredentialKind.OpenAiKey,
    pattern: /\bsk-[A-Za-z0-9]{20,}/g,
    placeholder: '[REDACTED:openai_key]',
  },
  {
    kind: CredentialKind.GitHubToken,
    pattern: /\b(?:ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}/g,
    placeholder: '[REDACTED:github_token]',
  },
  {
    kind: CredentialKind.AwsKey,
    pattern: /\bAKIA[A-Z0-9]{16,}/g,
    placeholder: '[REDACTED:aws_key]',
  },
  {
    kind: CredentialKind.PemKey,
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    placeholder: '[REDACTED:pem_key]',
  },
  {
    kind: CredentialKind.JwtToken,
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    placeholder: '[REDACTED:jwt_token]',
  },
  {
    kind: CredentialKind.BearerToken,
    pattern: /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    placeholder: '[REDACTED:bearer_token]',
  },
  {
    kind: CredentialKind.AzureConnectionString,
    pattern: /\b(?:DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)=[^;\n]+(?:;[^;\n]+){2,}/gi,
    placeholder: '[REDACTED:azure_connection_string]',
  },
  {
    kind: CredentialKind.ConnectionString,
    pattern: /\b(?:server|host|endpoint)=[^;]+;[^;\n]*(?:password|sharedaccesskey)=[^;\n]+/gi,
    placeholder: '[REDACTED:connection_string]',
  },
  {
    kind: CredentialKind.ApiKey,
    pattern: /(?:api[_-]?key|x-api-key)\s*[:=]\s*["']?[A-Za-z0-9_\-]{8,}["']?/gi,
    placeholder: '[REDACTED:api_key]',
  },
  {
    kind: CredentialKind.SecretAssignment,
    pattern: /\b(?:password|secret|token)\s*[:=]\s*["']?[^\s"';,]{4,}["']?/gi,
    placeholder: '[REDACTED:secret]',
  },
];

/**
 * Detects and redacts credential-like material from text.
 * Matches 10 credential patterns aligned with the Python CredentialRedactor.
 */
export class CredentialRedactor {
  /** Redact all detected credentials, returning sanitized text and findings. */
  redact(input: string): RedactionResult {
    let sanitized = input;
    const detected = new Set<CredentialKind>();

    for (const { kind, pattern, placeholder } of PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      if (re.test(sanitized)) {
        detected.add(kind);
        sanitized = sanitized.replace(new RegExp(pattern.source, pattern.flags), placeholder);
      }
    }

    return {
      sanitized,
      detected: Array.from(detected),
      modified: sanitized !== input,
    };
  }

  /** Check if text contains any credentials without redacting. */
  containsCredentials(input: string): boolean {
    for (const { pattern } of PATTERNS) {
      if (new RegExp(pattern.source, pattern.flags).test(input)) return true;
    }
    return false;
  }

  /** Return which credential types are present. */
  detectTypes(input: string): CredentialKind[] {
    const found: CredentialKind[] = [];
    for (const { kind, pattern } of PATTERNS) {
      if (new RegExp(pattern.source, pattern.flags).test(input)) found.push(kind);
    }
    return found;
  }

  /** Find all credential matches with masked snippets (safe for logging/audit). */
  findMatches(input: string): CredentialMatch[] {
    return this.findMatchesRaw(input).map(({ kind, matched }) => ({
      kind,
      matched: matched.length > 4 ? matched.slice(0, 4) + '***' : '***',
    }));
  }

  /**
   * Find all credential matches with full raw text.
   * **WARNING:** Results contain unmasked secrets — do NOT log or persist.
   */
  findMatchesRaw(input: string): CredentialMatchRaw[] {
    const matches: CredentialMatchRaw[] = [];
    for (const { kind, pattern } of PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(input)) !== null) {
        matches.push({ kind, matched: m[0] });
      }
    }
    return matches;
  }
}
