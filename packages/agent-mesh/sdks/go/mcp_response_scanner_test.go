// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"testing"
	"time"
)

func TestMcpResponseScannerRedactsNestedCredentials(t *testing.T) {
	scanner, err := NewMcpResponseScanner(McpResponseScannerConfig{})
	if err != nil {
		t.Fatalf("NewMcpResponseScanner: %v", err)
	}
	result := scanner.ScanResponse(map[string]any{
		"headers": map[string]any{
			"x-api-key": "abcdefghijklmnop",
		},
		"message": "Authorization: Bearer token1234567890",
	})
	if !result.Modified {
		t.Fatal("expected response to be modified")
	}
	sanitized := result.Sanitized.(map[string]any)
	headers := sanitized["headers"].(map[string]any)
	if headers["x-api-key"] != mcpRedactedAPIKey {
		t.Fatalf("expected x-api-key redaction, got %#v", headers["x-api-key"])
	}
	if sanitized["message"] == "Authorization: Bearer token1234567890" {
		t.Fatalf("expected bearer token redaction, got %#v", sanitized["message"])
	}
}

func TestMcpResponseScannerTimesOut(t *testing.T) {
	call := 0
	scanner, err := NewMcpResponseScanner(McpResponseScannerConfig{
		Clock: func() time.Time {
			call++
			return time.Unix(0, int64(call)*int64(200*time.Millisecond))
		},
		RegexTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewMcpResponseScanner: %v", err)
	}
	result := scanner.ScanResponse(map[string]any{"message": "safe"})
	if !result.Modified {
		t.Fatal("expected timeout result to be marked modified")
	}
	if len(result.Threats) == 0 || result.Threats[0].Type != McpThreatScannerFailure {
		t.Fatalf("expected scanner failure threat, got %+v", result.Threats)
	}
}
