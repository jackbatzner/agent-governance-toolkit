// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	mcpRedactedAPIKey           = "[REDACTED_API_KEY]"
	mcpRedactedBearerToken      = "[REDACTED_BEARER_TOKEN]"
	mcpRedactedConnectionString = "[REDACTED_CONNECTION_STRING]"
	mcpRedactedSecret           = "[REDACTED_SECRET]"
	mcpRedactedPEM              = "[REDACTED_PEM_BLOCK]"
	mcpRedactedScanTimeout      = "[REDACTED_SCAN_TIMEOUT]"
)

// McpRedactionPattern adds custom redaction support.
type McpRedactionPattern struct {
	Name        string
	Pattern     string
	Replacement string
	Severity    McpSeverity
}

// RedactionResult captures sanitized output and detected threats.
type RedactionResult struct {
	Sanitized string      `json:"sanitized"`
	Threats   []McpThreat `json:"threats"`
	Modified  bool        `json:"modified"`
	TimedOut  bool        `json:"timed_out"`
}

type mcpCompiledRedactionPattern struct {
	name        string
	regex       *regexp.Regexp
	replacement string
	severity    McpSeverity
	threatType  McpThreatType
}

// CredentialRedactor strips sensitive credential material from audit payloads.
type CredentialRedactor struct {
	clock    McpClock
	budget   time.Duration
	patterns []mcpCompiledRedactionPattern
}

// CredentialRedactorConfig configures scan budgets and custom patterns.
type CredentialRedactorConfig struct {
	Clock          McpClock
	RegexTimeout   time.Duration
	CustomPatterns []McpRedactionPattern
}

// NewCredentialRedactor builds a credential redactor with safe default patterns.
func NewCredentialRedactor(config CredentialRedactorConfig) (*CredentialRedactor, error) {
	if config.RegexTimeout <= 0 {
		config.RegexTimeout = defaultMcpRegexBudget
	}
	patterns, err := buildMcpRedactionPatterns(config.CustomPatterns)
	if err != nil {
		return nil, err
	}
	return &CredentialRedactor{
		clock:    normalizeMcpClock(config.Clock),
		budget:   config.RegexTimeout,
		patterns: patterns,
	}, nil
}

// Redact removes credentials and private key blocks from a string.
func (r *CredentialRedactor) Redact(input string) (result RedactionResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = RedactionResult{
				Sanitized: mcpRedactedScanTimeout,
				Modified:  true,
				TimedOut:  true,
				Threats: []McpThreat{
					mcpThreat(McpThreatScannerFailure, McpSeverityCritical, "", "", fmt.Sprintf("credential redaction failed closed: %v", recovered), nil),
				},
			}
		}
	}()
	if r == nil {
		return RedactionResult{
			Sanitized: mcpRedactedScanTimeout,
			Modified:  true,
			TimedOut:  true,
			Threats: []McpThreat{
				mcpThreat(McpThreatScannerFailure, McpSeverityCritical, "", "", "credential redactor was nil", nil),
			},
		}
	}
	start := r.clock()
	sanitized := input
	threats := make([]McpThreat, 0, 2)
	seen := make(map[string]struct{})
	for _, pattern := range r.patterns {
		if r.clock().Sub(start) > r.budget {
			return RedactionResult{
				Sanitized: mcpRedactedScanTimeout,
				Modified:  true,
				TimedOut:  true,
				Threats: append(threats, mcpThreat(
					McpThreatScannerFailure,
					McpSeverityCritical,
					"",
					"",
					"credential redaction scan budget exceeded",
					map[string]any{"budget_ms": r.budget.Milliseconds()},
				)),
			}
		}
		if !pattern.regex.MatchString(sanitized) {
			continue
		}
		sanitized = pattern.regex.ReplaceAllString(sanitized, pattern.replacement)
		key := string(pattern.threatType) + ":" + pattern.name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		threats = append(threats, mcpThreat(
			pattern.threatType,
			pattern.severity,
			"",
			pattern.name,
			fmt.Sprintf("redacted %s", pattern.name),
			map[string]any{"replacement": pattern.replacement},
		))
	}
	return RedactionResult{
		Sanitized: sanitized,
		Modified:  sanitized != input,
		Threats:   threats,
	}
}

func buildMcpRedactionPatterns(customPatterns []McpRedactionPattern) ([]mcpCompiledRedactionPattern, error) {
	patterns := []mcpCompiledRedactionPattern{
		mustCompileMcpPattern("rsa_private_key", `(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----`, mcpRedactedPEM, McpSeverityCritical, McpThreatPemExposure),
		mustCompileMcpPattern("ec_private_key", `(?s)-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----`, mcpRedactedPEM, McpSeverityCritical, McpThreatPemExposure),
		mustCompileMcpPattern("dsa_private_key", `(?s)-----BEGIN DSA PRIVATE KEY-----.*?-----END DSA PRIVATE KEY-----`, mcpRedactedPEM, McpSeverityCritical, McpThreatPemExposure),
		mustCompileMcpPattern("openssh_private_key", `(?s)-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----`, mcpRedactedPEM, McpSeverityCritical, McpThreatPemExposure),
		mustCompileMcpPattern("encrypted_private_key", `(?s)-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----`, mcpRedactedPEM, McpSeverityCritical, McpThreatPemExposure),
		mustCompileMcpPattern("openai_key", `\bsk-[A-Za-z0-9]{20,}\b`, mcpRedactedAPIKey, McpSeverityCritical, McpThreatCredentialLeakage),
		mustCompileMcpPattern("github_pat", `\bghp_[A-Za-z0-9]{20,}\b`, mcpRedactedAPIKey, McpSeverityCritical, McpThreatCredentialLeakage),
		mustCompileMcpPattern("bearer_token", `(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{10,}\b`, mcpRedactedBearerToken, McpSeverityCritical, McpThreatCredentialLeakage),
		mustCompileMcpPattern("api_key_assignment", `(?i)(?:api[_-]?key|x-api-key)\s*[:=]\s*["']?[^"'\s;,]{8,}`, mcpRedactedAPIKey, McpSeverityCritical, McpThreatCredentialLeakage),
		mustCompileMcpPattern("connection_string", `(?i)\b(?:server|host|endpoint|accountendpoint)=[^;\n]+;[^;\n]*(?:password|sharedaccesskey|accountkey)=[^;\n]+`, mcpRedactedConnectionString, McpSeverityCritical, McpThreatCredentialLeakage),
		mustCompileMcpPattern("secret_assignment", `(?i)\b(?:password|secret|token|client_secret)\s*[:=]\s*["']?[^"'\s;,]{4,}`, mcpRedactedSecret, McpSeverityWarning, McpThreatCredentialLeakage),
	}
	for _, customPattern := range customPatterns {
		replacement := customPattern.Replacement
		if replacement == "" {
			replacement = "[REDACTED_CUSTOM_PATTERN]"
		}
		severity := customPattern.Severity
		if severity == "" {
			severity = McpSeverityWarning
		}
		regex, err := regexp.Compile(customPattern.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: compiling custom redaction pattern %q: %v", ErrMcpInvalidConfig, customPattern.Name, err)
		}
		patterns = append(patterns, mcpCompiledRedactionPattern{
			name:        customPattern.Name,
			regex:       regex,
			replacement: replacement,
			severity:    severity,
			threatType:  McpThreatCredentialLeakage,
		})
	}
	return patterns, nil
}

func mustCompileMcpPattern(name, expression, replacement string, severity McpSeverity, threatType McpThreatType) mcpCompiledRedactionPattern {
	return mcpCompiledRedactionPattern{
		name:        name,
		regex:       regexp.MustCompile(expression),
		replacement: replacement,
		severity:    severity,
		threatType:  threatType,
	}
}

func mcpSensitiveKeyReplacement(key string) (string, bool) {
	lower := strings.ToLower(key)
	switch {
	case strings.Contains(lower, "authorization"), strings.Contains(lower, "bearer"):
		return mcpRedactedBearerToken, true
	case strings.Contains(lower, "api_key"), strings.Contains(lower, "apikey"), strings.Contains(lower, "x-api-key"):
		return mcpRedactedAPIKey, true
	case strings.Contains(lower, "connection") && strings.Contains(lower, "string"):
		return mcpRedactedConnectionString, true
	case strings.Contains(lower, "password"), strings.Contains(lower, "secret"), strings.Contains(lower, "token"), strings.Contains(lower, "credential"):
		return mcpRedactedSecret, true
	default:
		return "", false
	}
}
