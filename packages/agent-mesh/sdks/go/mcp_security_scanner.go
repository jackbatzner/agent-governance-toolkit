// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// McpSecurityScannerConfig configures tool-definition scanning.
type McpSecurityScannerConfig struct {
	Clock        McpClock
	RegexTimeout time.Duration
	Metrics      *McpMetrics
}

// McpSecurityScanner scans MCP tool definitions for prompt-injection threats.
type McpSecurityScanner struct {
	mu                    sync.Mutex
	clock                 McpClock
	budget                time.Duration
	metrics               *McpMetrics
	fingerprints          map[string]McpToolFingerprint
	hiddenCommentPattern  *regexp.Regexp
	encodedPayloadPattern *regexp.Regexp
	injectionPattern      *regexp.Regexp
}

// NewMcpSecurityScanner creates a scanner with a fingerprint registry.
func NewMcpSecurityScanner(config McpSecurityScannerConfig) *McpSecurityScanner {
	if config.RegexTimeout <= 0 {
		config.RegexTimeout = defaultMcpRegexBudget
	}
	return &McpSecurityScanner{
		clock:                 normalizeMcpClock(config.Clock),
		budget:                config.RegexTimeout,
		metrics:               config.Metrics,
		fingerprints:          make(map[string]McpToolFingerprint),
		hiddenCommentPattern:  regexp.MustCompile(`(?s)<!--.*?-->|\[//\]:\s*#\s*\(.*?\)`),
		encodedPayloadPattern: regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
		injectionPattern:      regexp.MustCompile(`(?i)(ignore\s+(all\s+)?previous|override\s+(the\s+)?instructions|curl\s+https?://|wget\s+https?://|send\s+secrets|system\s+prompt|you\s+must)`),
	}
}

// ScanTool scans a tool definition and fails closed by returning a critical threat on internal error.
func (s *McpSecurityScanner) ScanTool(name, description string, schema any) (threats []McpThreat) {
	defer func() {
		if recovered := recover(); recovered != nil {
			threats = []McpThreat{
				mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", fmt.Sprintf("tool scan failed closed: %v", recovered), nil),
			}
		}
	}()
	if s == nil {
		return []McpThreat{
			mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", "tool scanner was nil", nil),
		}
	}
	s.metrics.RecordScan("tool_metadata")
	start := s.clock()
	if s.clock().Sub(start) > s.budget {
		return []McpThreat{
			mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", "tool scan budget exceeded", nil),
		}
	}

	threats = append(threats, s.detectDescriptionThreats(name, description)...)
	if s.clock().Sub(start) > s.budget {
		return append(threats, mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", "tool scan budget exceeded", nil))
	}
	if schemaThreats, err := s.detectSchemaThreats(name, schema); err != nil {
		return append(threats, mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", err.Error(), nil))
	} else {
		threats = append(threats, schemaThreats...)
	}
	if rugPullThreat, err := s.checkFingerprint(name, description, schema); err != nil {
		return append(threats, mcpThreat(McpThreatScannerFailure, McpSeverityCritical, name, "", err.Error(), nil))
	} else if rugPullThreat != nil {
		threats = append(threats, *rugPullThreat)
	}
	for _, threat := range threats {
		s.metrics.RecordThreat(threat.Type)
	}
	return threats
}

func (s *McpSecurityScanner) detectDescriptionThreats(name, description string) []McpThreat {
	var threats []McpThreat
	if containsMcpInvisibleUnicode(description) || s.hiddenCommentPattern.MatchString(description) {
		threats = append(threats, mcpThreat(
			McpThreatHiddenInstruction,
			McpSeverityCritical,
			name,
			"description",
			"hidden instruction markers detected in tool description",
			nil,
		))
	}
	if s.encodedPayloadPattern.MatchString(description) || strings.Contains(strings.ToLower(description), "base64") {
		threats = append(threats, mcpThreat(
			McpThreatToolPoisoning,
			McpSeverityCritical,
			name,
			"description",
			"encoded payload indicators detected in tool description",
			nil,
		))
	}
	if s.injectionPattern.MatchString(description) {
		threats = append(threats, mcpThreat(
			McpThreatDescriptionInjection,
			McpSeverityWarning,
			name,
			"description",
			"description contains prompt-like control language",
			nil,
		))
	}
	return threats
}

func (s *McpSecurityScanner) detectSchemaThreats(name string, schema any) ([]McpThreat, error) {
	if schema == nil {
		return nil, nil
	}
	encoded, err := canonicalMcpJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding schema: %v", ErrMcpFailClosed, err)
	}
	var normalized any
	if err := jsonUnmarshalMcp(encoded, &normalized); err != nil {
		return nil, fmt.Errorf("%w: decoding schema: %v", ErrMcpFailClosed, err)
	}
	var threats []McpThreat
	if mapValue, ok := normalized.(map[string]any); ok {
		if typeValue, _ := mapValue["type"].(string); typeValue == "object" {
			if properties, ok := mapValue["properties"].(map[string]any); !ok || len(properties) == 0 {
				threats = append(threats, mcpThreat(
					McpThreatSchemaAbuse,
					McpSeverityCritical,
					name,
					"schema",
					"schema is overly permissive",
					nil,
				))
			}
		}
		if required, ok := mapValue["required"].([]any); ok {
			var suspicious []string
			for _, entry := range required {
				field, ok := entry.(string)
				if !ok {
					continue
				}
				lower := strings.ToLower(field)
				if lower == "system_prompt" || lower == "secret" || lower == "token" || lower == "password" {
					suspicious = append(suspicious, field)
				}
			}
			if len(suspicious) > 0 {
				threats = append(threats, mcpThreat(
					McpThreatSchemaAbuse,
					McpSeverityWarning,
					name,
					"required",
					"schema requires sensitive or hidden fields",
					map[string]any{"fields": suspicious},
				))
			}
		}
	}
	if schemaContainsMcpInstruction(normalized) {
		threats = append(threats, mcpThreat(
			McpThreatSchemaAbuse,
			McpSeverityCritical,
			name,
			"schema",
			"schema contains instruction-bearing text",
			nil,
		))
	}
	return threats, nil
}

func (s *McpSecurityScanner) checkFingerprint(name, description string, schema any) (*McpThreat, error) {
	descriptionHash := sha256HexMcp(description)
	schemaJSON, err := canonicalMcpJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding fingerprint schema: %v", ErrMcpFailClosed, err)
	}
	schemaHash := sha256HexMcp(string(schemaJSON))
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fingerprints == nil {
		s.fingerprints = make(map[string]McpToolFingerprint)
	}
	existing, ok := s.fingerprints[name]
	if !ok {
		s.fingerprints[name] = McpToolFingerprint{
			ToolName:        name,
			DescriptionHash: descriptionHash,
			SchemaHash:      schemaHash,
			FirstSeen:       now,
			LastSeen:        now,
			Version:         1,
		}
		return nil, nil
	}
	changed := existing.DescriptionHash != descriptionHash || existing.SchemaHash != schemaHash
	if changed {
		existing.DescriptionHash = descriptionHash
		existing.SchemaHash = schemaHash
		existing.LastSeen = now
		existing.Version++
		s.fingerprints[name] = existing
		return &McpThreat{
			Type:     McpThreatRugPull,
			Severity: McpSeverityCritical,
			ToolName: name,
			Field:    "fingerprint",
			Message:  "tool definition drift detected",
			Details:  encodeMcpDetails(map[string]any{"version": existing.Version}),
		}, nil
	}
	existing.LastSeen = now
	s.fingerprints[name] = existing
	return nil, nil
}

func containsMcpInvisibleUnicode(input string) bool {
	for _, value := range input {
		switch {
		case value == '\u200b',
			value == '\u200c',
			value == '\u200d',
			value == '\ufeff',
			value >= '\u202a' && value <= '\u202e':
			return true
		}
	}
	return false
}

func schemaContainsMcpInstruction(value any) bool {
	switch typed := value.(type) {
	case string:
		lower := strings.ToLower(typed)
		return strings.Contains(lower, "ignore previous") ||
			strings.Contains(lower, "override") ||
			strings.Contains(lower, "send secrets")
	case []any:
		for _, item := range typed {
			if schemaContainsMcpInstruction(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if schemaContainsMcpInstruction(item) {
				return true
			}
		}
	}
	return false
}

func sha256HexMcp(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func jsonUnmarshalMcp(data []byte, destination any) error {
	return json.Unmarshal(data, destination)
}
