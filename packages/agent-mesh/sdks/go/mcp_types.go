// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"
)

const (
	defaultMcpNonceCacheSize = 4096
	defaultMcpRegexBudget    = 100 * time.Millisecond
	defaultMcpTokenBytes     = 32
	defaultMcpNonceBytes     = 18
	defaultMcpSessionTTL     = 15 * time.Minute
	defaultMcpSessionWindow  = time.Minute
	defaultMcpTimestampSkew  = 5 * time.Minute
	defaultMcpNonceTTL       = 10 * time.Minute
	defaultMcpBucketIdleTTL  = 2 * time.Minute
	defaultMcpMaxCreations   = 10
	defaultMcpMaxRequests    = 60
	defaultMcpPolicyDecision = Allow
)

var (
	// ErrMcpFailClosed indicates a security primitive denied the request on internal failure.
	ErrMcpFailClosed = errors.New("mcp security gate failed closed")
	// ErrMcpInvalidConfig indicates invalid MCP configuration.
	ErrMcpInvalidConfig = errors.New("invalid mcp configuration")
	// ErrMcpInvalidSignature indicates an invalid MCP signature.
	ErrMcpInvalidSignature = errors.New("invalid mcp signature")
	// ErrMcpReplayDetected indicates a replayed signed MCP message.
	ErrMcpReplayDetected = errors.New("mcp replay detected")
	// ErrMcpSessionExpired indicates an expired MCP session.
	ErrMcpSessionExpired = errors.New("mcp session expired")
	// ErrMcpSessionNotFound indicates a missing MCP session.
	ErrMcpSessionNotFound = errors.New("mcp session not found")
	// ErrMcpSessionLimitExceeded indicates too many active MCP sessions for an agent.
	ErrMcpSessionLimitExceeded = errors.New("mcp session limit exceeded")
	// ErrMcpRateLimited indicates an MCP request was rate limited.
	ErrMcpRateLimited = errors.New("mcp request rate limited")
	// ErrMcpPolicyDenied indicates MCP policy denied a tool call.
	ErrMcpPolicyDenied = errors.New("mcp policy denied tool call")
	// ErrMcpApprovalRequired indicates MCP policy requires explicit approval.
	ErrMcpApprovalRequired = errors.New("mcp approval required")
)

// McpClock provides deterministic time for security primitives.
type McpClock func() time.Time

// McpTokenGenerator generates deterministic or random tokens for tests and runtime use.
type McpTokenGenerator func() (string, error)

// McpSeverity classifies the seriousness of a detected threat.
type McpSeverity string

const (
	McpSeverityInfo     McpSeverity = "info"
	McpSeverityWarning  McpSeverity = "warning"
	McpSeverityCritical McpSeverity = "critical"
)

// McpThreatType categorizes MCP threats detected by scanners and gateways.
type McpThreatType string

const (
	McpThreatHiddenInstruction    McpThreatType = "hidden_instruction"
	McpThreatDescriptionInjection McpThreatType = "description_injection"
	McpThreatToolPoisoning        McpThreatType = "tool_poisoning"
	McpThreatRugPull              McpThreatType = "rug_pull"
	McpThreatSchemaAbuse          McpThreatType = "schema_abuse"
	McpThreatCredentialLeakage    McpThreatType = "credential_leakage"
	McpThreatPemExposure          McpThreatType = "pem_exposure"
	McpThreatScannerFailure       McpThreatType = "scanner_failure"
)

// McpThreat captures a security finding without storing raw secrets.
type McpThreat struct {
	Type     McpThreatType   `json:"type"`
	Severity McpSeverity     `json:"severity"`
	ToolName string          `json:"tool_name,omitempty"`
	Field    string          `json:"field,omitempty"`
	Message  string          `json:"message"`
	Details  json.RawMessage `json:"details,omitempty"`
}

// McpToolFingerprint tracks tool metadata drift over time.
type McpToolFingerprint struct {
	ToolName        string    `json:"tool_name"`
	DescriptionHash string    `json:"description_hash"`
	SchemaHash      string    `json:"schema_hash"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Version         uint64    `json:"version"`
}

// McpSignedEnvelope represents an HMAC-signed MCP payload.
type McpSignedEnvelope struct {
	AgentID   string    `json:"agent_id,omitempty"`
	ToolName  string    `json:"tool_name,omitempty"`
	Payload   any       `json:"payload,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	Signature string    `json:"signature,omitempty"`
}

// McpSession stores authenticated session state for an MCP caller.
type McpSession struct {
	Token     string    `json:"token"`
	AgentID   string    `json:"agent_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// McpRateLimitDecision is the result of a rate-limit evaluation.
type McpRateLimitDecision struct {
	Allowed    bool          `json:"allowed"`
	Remaining  int           `json:"remaining"`
	RetryAfter time.Duration `json:"retry_after"`
}

// McpResponseScanResult contains a sanitized response and credential findings.
type McpResponseScanResult struct {
	Sanitized any         `json:"sanitized"`
	Threats   []McpThreat `json:"threats"`
	Modified  bool        `json:"modified"`
}

// McpToolCallRequest is evaluated by the gateway before a tool executes.
type McpToolCallRequest struct {
	AgentID         string `json:"agent_id"`
	SessionToken    string `json:"session_token"`
	ToolName        string `json:"tool_name"`
	ToolDescription string `json:"tool_description,omitempty"`
	ToolSchema      any    `json:"tool_schema,omitempty"`
	Payload         any    `json:"payload,omitempty"`
}

// McpPolicy configures gateway allow, deny, and approval rules.
type McpPolicy struct {
	AllowPatterns     []string       `json:"allow_patterns,omitempty"`
	DenyPatterns      []string       `json:"deny_patterns,omitempty"`
	ApprovalPatterns  []string       `json:"approval_patterns,omitempty"`
	BlockOnSeverities []McpSeverity  `json:"block_on_severities,omitempty"`
	AutoApprove       bool           `json:"auto_approve"`
	DefaultDecision   PolicyDecision `json:"default_decision"`
}

// DefaultMcpPolicy returns an allow-by-default policy that blocks critical threats.
func DefaultMcpPolicy() McpPolicy {
	return McpPolicy{
		BlockOnSeverities: []McpSeverity{McpSeverityCritical},
		DefaultDecision:   defaultMcpPolicyDecision,
	}
}

// McpGatewayDecision is the terminal result of gateway enforcement.
type McpGatewayDecision struct {
	Allowed          bool               `json:"allowed"`
	Decision         PolicyDecision     `json:"decision"`
	Reason           string             `json:"reason,omitempty"`
	Threats          []McpThreat        `json:"threats,omitempty"`
	SanitizedPayload any                `json:"sanitized_payload,omitempty"`
	SignedEnvelope   *McpSignedEnvelope `json:"signed_envelope,omitempty"`
	Session          *McpSession        `json:"session,omitempty"`
	AuditEntry       *AuditEntry        `json:"audit_entry,omitempty"`
	RetryAfter       time.Duration      `json:"retry_after,omitempty"`
}

func normalizeMcpClock(clock McpClock) McpClock {
	if clock != nil {
		return clock
	}
	return func() time.Time {
		return time.Now().UTC()
	}
}

func defaultMcpTokenGenerator(byteLength int) McpTokenGenerator {
	return func() (string, error) {
		buffer := make([]byte, byteLength)
		if _, err := rand.Read(buffer); err != nil {
			return "", fmt.Errorf("reading random bytes: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(buffer), nil
	}
}

func canonicalMcpJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical json: %w", err)
	}
	return data, nil
}

func matchMcpPattern(patternValue, candidate string) bool {
	if patternValue == "" {
		return false
	}
	matched, err := path.Match(patternValue, candidate)
	if err == nil {
		return matched
	}
	return patternValue == candidate
}

func encodeMcpDetails(value any) json.RawMessage {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{"error":"failed to encode details"}`)
	}
	return json.RawMessage(data)
}

func mcpThreat(typeValue McpThreatType, severity McpSeverity, toolName, field, message string, details any) McpThreat {
	return McpThreat{
		Type:     typeValue,
		Severity: severity,
		ToolName: toolName,
		Field:    field,
		Message:  message,
		Details:  encodeMcpDetails(details),
	}
}

func mcpWorstSeverity(threats []McpThreat) McpSeverity {
	worst := McpSeverityInfo
	for _, threat := range threats {
		if severityRank(threat.Severity) > severityRank(worst) {
			worst = threat.Severity
		}
	}
	return worst
}

func severityRank(severity McpSeverity) int {
	switch severity {
	case McpSeverityCritical:
		return 3
	case McpSeverityWarning:
		return 2
	default:
		return 1
	}
}
