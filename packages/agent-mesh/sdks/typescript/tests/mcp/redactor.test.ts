// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor, CredentialKind } from '../../src/mcp/redactor';

describe('CredentialRedactor', () => {
  let redactor: CredentialRedactor;

  beforeEach(() => {
    redactor = new CredentialRedactor();
  });

  // ── Clean text ──

  it('returns unmodified result for clean text', () => {
    const result = redactor.redact('Hello, this is perfectly clean text.');
    expect(result.modified).toBe(false);
    expect(result.detected).toHaveLength(0);
    expect(result.sanitized).toBe('Hello, this is perfectly clean text.');
  });

  it('containsCredentials returns false for clean text', () => {
    expect(redactor.containsCredentials('No secrets here.')).toBe(false);
  });

  // ── OpenAI key ──

  it('detects and redacts OpenAI key', () => {
    const input = 'Key is sk-abcdefghijklmnopqrstuvwx';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.OpenAiKey);
    expect(result.sanitized).toContain('[REDACTED:openai_key]');
    expect(result.sanitized).not.toContain('sk-abcdefghijklmnopqrstuvwx');
  });

  // ── GitHub token ──

  it('detects and redacts GitHub token', () => {
    const input = 'Use ghp_abcdefghijklmnopqrstuvwxyz1234 for auth';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.GitHubToken);
    expect(result.sanitized).toContain('[REDACTED:github_token]');
    expect(result.sanitized).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz1234');
  });

  // ── AWS key ──

  it('detects and redacts AWS key', () => {
    const input = 'AWS key: AKIAIOSFODNN7EXAMPLE';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.AwsKey);
    expect(result.sanitized).toContain('[REDACTED:aws_key]');
  });

  // ── Bearer token ──

  it('detects and redacts Bearer token', () => {
    const input = 'Authorization: bearer eyJhbGciOiJIUzI1NiJ9.test.value';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.BearerToken);
    expect(result.sanitized).toContain('[REDACTED:bearer_token]');
  });

  // ── Connection string ──

  it('detects and redacts connection string', () => {
    const input = 'server=myhost;password=secret123';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.ConnectionString);
    expect(result.sanitized).toContain('[REDACTED:connection_string]');
  });

  // ── Secret assignment ──

  it('detects and redacts secret assignment', () => {
    const input = 'password=mysecret123';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.SecretAssignment);
    expect(result.sanitized).toContain('[REDACTED:secret]');
  });

  // ── Azure connection string ──

  it('detects and redacts Azure connection string', () => {
    const input = 'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.AzureConnectionString);
    expect(result.sanitized).toContain('[REDACTED:azure_connection_string]');
  });

  // ── PEM key ──

  it('detects and redacts PEM private key', () => {
    const input = '-----BEGIN PRIVATE KEY-----\nMIIEvgIB...\n-----END PRIVATE KEY-----';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.PemKey);
    expect(result.sanitized).toContain('[REDACTED:pem_key]');
  });

  // ── JWT ──

  it('detects and redacts JWT token', () => {
    const input =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.JwtToken);
    expect(result.sanitized).toContain('[REDACTED:jwt_token]');
  });

  // ── API key ──

  it('detects and redacts API key assignment', () => {
    const input = 'api_key=abcd1234efgh5678';
    const result = redactor.redact(input);
    expect(result.modified).toBe(true);
    expect(result.detected).toContain(CredentialKind.ApiKey);
    expect(result.sanitized).toContain('[REDACTED:api_key]');
  });

  // ── containsCredentials ──

  it('containsCredentials returns true when credentials present', () => {
    expect(redactor.containsCredentials('key: sk-abcdefghijklmnopqrstuvwx')).toBe(true);
  });

  // ── detectTypes ──

  it('detectTypes lists found credential kinds', () => {
    const input = 'sk-abcdefghijklmnopqrstuvwx and AKIAIOSFODNN7EXAMPLE';
    const types = redactor.detectTypes(input);
    expect(types).toContain(CredentialKind.OpenAiKey);
    expect(types).toContain(CredentialKind.AwsKey);
  });

  // ── findMatches (masked) ──

  it('findMatches returns masked CredentialMatch objects', () => {
    const input = 'Use ghp_abcdefghijklmnopqrstuvwxyz1234 for auth';
    const matches = redactor.findMatches(input);
    expect(matches.length).toBeGreaterThanOrEqual(1);
    const ghMatch = matches.find((m) => m.kind === CredentialKind.GitHubToken);
    expect(ghMatch).toBeDefined();
    expect(ghMatch!.matched).toContain('ghp_');
    expect(ghMatch!.matched).toContain('***');
    expect(ghMatch!.matched.length).toBeLessThan('ghp_abcdefghijklmnopqrstuvwxyz1234'.length);
  });

  // ── findMatchesRaw ──

  it('findMatchesRaw returns full unmasked credential text', () => {
    const input = 'Use ghp_abcdefghijklmnopqrstuvwxyz1234 for auth';
    const matches = redactor.findMatchesRaw(input);
    expect(matches.length).toBeGreaterThanOrEqual(1);
    const ghMatch = matches.find((m) => m.kind === CredentialKind.GitHubToken);
    expect(ghMatch).toBeDefined();
    expect(ghMatch!.matched).toBe('ghp_abcdefghijklmnopqrstuvwxyz1234');
  });
});
