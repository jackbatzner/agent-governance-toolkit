// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// McpResponseScannerConfig configures response scanning.
type McpResponseScannerConfig struct {
	Clock        McpClock
	RegexTimeout time.Duration
	Redactor     *CredentialRedactor
	Metrics      *McpMetrics
}

// McpResponseScanner scans tool responses for leaked credentials.
type McpResponseScanner struct {
	clock    McpClock
	budget   time.Duration
	redactor *CredentialRedactor
	metrics  *McpMetrics
}

// NewMcpResponseScanner creates a response scanner backed by the credential redactor.
func NewMcpResponseScanner(config McpResponseScannerConfig) (*McpResponseScanner, error) {
	if config.RegexTimeout <= 0 {
		config.RegexTimeout = defaultMcpRegexBudget
	}
	if config.Redactor == nil {
		redactor, err := NewCredentialRedactor(CredentialRedactorConfig{
			Clock:        config.Clock,
			RegexTimeout: config.RegexTimeout,
		})
		if err != nil {
			return nil, err
		}
		config.Redactor = redactor
	}
	return &McpResponseScanner{
		clock:    normalizeMcpClock(config.Clock),
		budget:   config.RegexTimeout,
		redactor: config.Redactor,
		metrics:  config.Metrics,
	}, nil
}

// ScanResponse sanitizes credential leaks from strings and JSON-like responses.
func (s *McpResponseScanner) ScanResponse(response any) (result McpResponseScanResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = McpResponseScanResult{
				Sanitized: mcpRedactedScanTimeout,
				Modified:  true,
				Threats: []McpThreat{
					mcpThreat(McpThreatScannerFailure, McpSeverityCritical, "", "", fmt.Sprintf("response scan failed closed: %v", recovered), nil),
				},
			}
		}
	}()
	if s == nil {
		return McpResponseScanResult{
			Sanitized: mcpRedactedScanTimeout,
			Modified:  true,
			Threats: []McpThreat{
				mcpThreat(McpThreatScannerFailure, McpSeverityCritical, "", "", "response scanner was nil", nil),
			},
		}
	}
	s.metrics.RecordScan("response")
	start := s.clock()
	sanitized, threats, modified := s.scanValue("", response, start)
	for _, threat := range threats {
		s.metrics.RecordThreat(threat.Type)
	}
	return McpResponseScanResult{
		Sanitized: sanitized,
		Threats:   threats,
		Modified:  modified,
	}
}

func (s *McpResponseScanner) scanValue(field string, value any, start time.Time) (any, []McpThreat, bool) {
	if s.clock().Sub(start) > s.budget {
		return mcpRedactedScanTimeout, []McpThreat{
			mcpThreat(McpThreatScannerFailure, McpSeverityCritical, "", field, "response scan budget exceeded", map[string]any{"budget_ms": s.budget.Milliseconds()}),
		}, true
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil, false
	case string:
		if replacement, ok := mcpSensitiveKeyReplacement(field); ok && typed != replacement {
			return replacement, []McpThreat{
				mcpThreat(McpThreatCredentialLeakage, McpSeverityCritical, "", field, "redacted credential-looking field", nil),
			}, true
		}
		redaction := s.redactor.Redact(typed)
		return redaction.Sanitized, redaction.Threats, redaction.Modified
	case []any:
		return s.scanSlice(typed, start)
	case map[string]any:
		return s.scanMap(typed, start)
	default:
		normalized, ok := normalizeMcpResponseValue(typed)
		if !ok {
			return value, nil, false
		}
		return s.scanValue(field, normalized, start)
	}
}

func (s *McpResponseScanner) scanSlice(items []any, start time.Time) (any, []McpThreat, bool) {
	sanitized := make([]any, 0, len(items))
	var threats []McpThreat
	modified := false
	for _, item := range items {
		value, itemThreats, itemModified := s.scanValue("", item, start)
		sanitized = append(sanitized, value)
		threats = append(threats, itemThreats...)
		modified = modified || itemModified
	}
	return sanitized, threats, modified
}

func (s *McpResponseScanner) scanMap(values map[string]any, start time.Time) (any, []McpThreat, bool) {
	sanitized := make(map[string]any, len(values))
	var threats []McpThreat
	modified := false
	for key, value := range values {
		sanitizedValue, itemThreats, itemModified := s.scanValue(key, value, start)
		sanitized[key] = sanitizedValue
		threats = append(threats, itemThreats...)
		modified = modified || itemModified
	}
	return sanitized, threats, modified
}

func normalizeMcpResponseValue(value any) (any, bool) {
	if value == nil {
		return nil, true
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Map, reflect.Struct, reflect.Slice, reflect.Array:
		data, err := json.Marshal(value)
		if err != nil {
			return nil, false
		}
		var normalized any
		if err := json.Unmarshal(data, &normalized); err != nil {
			return nil, false
		}
		return normalized, true
	default:
		return nil, false
	}
}
