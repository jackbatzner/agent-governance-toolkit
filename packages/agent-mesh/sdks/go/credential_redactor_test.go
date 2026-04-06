// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"strings"
	"testing"
	"time"
)

func TestCredentialRedactorRedactsSecretsAndPEMBlocks(t *testing.T) {
	redactor, err := NewCredentialRedactor(CredentialRedactorConfig{})
	if err != nil {
		t.Fatalf("NewCredentialRedactor: %v", err)
	}
	input := "Authorization: Bearer token1234567890 sk-abcdefghijklmnopqrstuvwxyz12 -----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"
	result := redactor.Redact(input)
	if !result.Modified {
		t.Fatal("expected redaction to modify the input")
	}
	if strings.Contains(result.Sanitized, "Bearer token1234567890") || strings.Contains(result.Sanitized, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("expected secrets to be removed, got %q", result.Sanitized)
	}
	if len(result.Threats) < 2 {
		t.Fatalf("expected multiple threats, got %d", len(result.Threats))
	}
}

func TestCredentialRedactorSupportsCustomPatterns(t *testing.T) {
	redactor, err := NewCredentialRedactor(CredentialRedactorConfig{
		CustomPatterns: []McpRedactionPattern{
			{
				Name:        "tenant_secret",
				Pattern:     `tenant_secret=[A-Za-z0-9]+`,
				Replacement: "[REDACTED_TENANT_SECRET]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCredentialRedactor: %v", err)
	}
	result := redactor.Redact("tenant_secret=supersecret")
	if result.Sanitized != "[REDACTED_TENANT_SECRET]" {
		t.Fatalf("unexpected sanitized value %q", result.Sanitized)
	}
}

func TestCredentialRedactorTimesOut(t *testing.T) {
	call := 0
	redactor, err := NewCredentialRedactor(CredentialRedactorConfig{
		Clock: func() time.Time {
			call++
			return time.Unix(0, int64(call)*int64(200*time.Millisecond))
		},
		RegexTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCredentialRedactor: %v", err)
	}
	result := redactor.Redact("Bearer token1234567890")
	if !result.TimedOut {
		t.Fatal("expected timeout protection to trigger")
	}
}
