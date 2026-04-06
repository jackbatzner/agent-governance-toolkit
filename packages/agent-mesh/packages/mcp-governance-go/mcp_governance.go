// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpgovernance

import agentmesh "github.com/microsoft/agent-governance-toolkit/sdks/go"

type (
	PolicyDecision = agentmesh.PolicyDecision

	AuditEntry  = agentmesh.AuditEntry
	AuditLogger = agentmesh.AuditLogger

	McpClock              = agentmesh.McpClock
	McpTokenGenerator     = agentmesh.McpTokenGenerator
	McpSeverity           = agentmesh.McpSeverity
	McpThreatType         = agentmesh.McpThreatType
	McpThreat             = agentmesh.McpThreat
	McpToolFingerprint    = agentmesh.McpToolFingerprint
	McpSignedEnvelope     = agentmesh.McpSignedEnvelope
	McpSession            = agentmesh.McpSession
	McpRateLimitDecision  = agentmesh.McpRateLimitDecision
	McpResponseScanResult = agentmesh.McpResponseScanResult
	McpToolCallRequest    = agentmesh.McpToolCallRequest
	McpPolicy             = agentmesh.McpPolicy
	McpGatewayDecision    = agentmesh.McpGatewayDecision

	McpMetrics         = agentmesh.McpMetrics
	McpMetricsSnapshot = agentmesh.McpMetricsSnapshot

	SignerNonceStore         = agentmesh.SignerNonceStore
	InMemorySignerNonceStore = agentmesh.InMemorySignerNonceStore
	McpMessageSignerConfig   = agentmesh.McpMessageSignerConfig
	McpMessageSigner         = agentmesh.McpMessageSigner

	SessionStore                  = agentmesh.SessionStore
	InMemorySessionStore          = agentmesh.InMemorySessionStore
	McpSessionAuthenticator       = agentmesh.McpSessionAuthenticator
	McpSessionAuthenticatorConfig = agentmesh.McpSessionAuthenticatorConfig

	RateLimitStore              = agentmesh.RateLimitStore
	InMemoryRateLimitStore      = agentmesh.InMemoryRateLimitStore
	McpSlidingRateLimiter       = agentmesh.McpSlidingRateLimiter
	McpSlidingRateLimiterConfig = agentmesh.McpSlidingRateLimiterConfig

	McpRedactionPattern      = agentmesh.McpRedactionPattern
	RedactionResult          = agentmesh.RedactionResult
	CredentialRedactor       = agentmesh.CredentialRedactor
	CredentialRedactorConfig = agentmesh.CredentialRedactorConfig

	McpResponseScanner       = agentmesh.McpResponseScanner
	McpResponseScannerConfig = agentmesh.McpResponseScannerConfig

	McpSecurityScanner       = agentmesh.McpSecurityScanner
	McpSecurityScannerConfig = agentmesh.McpSecurityScannerConfig

	McpGateway       = agentmesh.McpGateway
	McpGatewayConfig = agentmesh.McpGatewayConfig
)

const (
	Allow            = agentmesh.Allow
	Deny             = agentmesh.Deny
	Review           = agentmesh.Review
	RateLimit        = agentmesh.RateLimit
	RequiresApproval = agentmesh.RequiresApproval

	McpSeverityInfo     = agentmesh.McpSeverityInfo
	McpSeverityWarning  = agentmesh.McpSeverityWarning
	McpSeverityCritical = agentmesh.McpSeverityCritical

	McpThreatHiddenInstruction    = agentmesh.McpThreatHiddenInstruction
	McpThreatDescriptionInjection = agentmesh.McpThreatDescriptionInjection
	McpThreatToolPoisoning        = agentmesh.McpThreatToolPoisoning
	McpThreatRugPull              = agentmesh.McpThreatRugPull
	McpThreatSchemaAbuse          = agentmesh.McpThreatSchemaAbuse
	McpThreatCredentialLeakage    = agentmesh.McpThreatCredentialLeakage
	McpThreatPemExposure          = agentmesh.McpThreatPemExposure
	McpThreatScannerFailure       = agentmesh.McpThreatScannerFailure

	McpMetricDecisions  = agentmesh.McpMetricDecisions
	McpMetricRateLimits = agentmesh.McpMetricRateLimits
	McpMetricScans      = agentmesh.McpMetricScans
	McpMetricThreats    = agentmesh.McpMetricThreats
)

var (
	ErrMcpFailClosed           = agentmesh.ErrMcpFailClosed
	ErrMcpInvalidConfig        = agentmesh.ErrMcpInvalidConfig
	ErrMcpInvalidSignature     = agentmesh.ErrMcpInvalidSignature
	ErrMcpReplayDetected       = agentmesh.ErrMcpReplayDetected
	ErrMcpSessionExpired       = agentmesh.ErrMcpSessionExpired
	ErrMcpSessionNotFound      = agentmesh.ErrMcpSessionNotFound
	ErrMcpSessionLimitExceeded = agentmesh.ErrMcpSessionLimitExceeded
	ErrMcpRateLimited          = agentmesh.ErrMcpRateLimited
	ErrMcpPolicyDenied         = agentmesh.ErrMcpPolicyDenied
	ErrMcpApprovalRequired     = agentmesh.ErrMcpApprovalRequired

	DefaultMcpPolicy            = agentmesh.DefaultMcpPolicy
	NewMcpMetrics               = agentmesh.NewMcpMetrics
	NewInMemorySignerNonceStore = agentmesh.NewInMemorySignerNonceStore
	NewMcpMessageSigner         = agentmesh.NewMcpMessageSigner
	NewInMemorySessionStore     = agentmesh.NewInMemorySessionStore
	NewMcpSessionAuthenticator  = agentmesh.NewMcpSessionAuthenticator
	NewInMemoryRateLimitStore   = agentmesh.NewInMemoryRateLimitStore
	NewMcpSlidingRateLimiter    = agentmesh.NewMcpSlidingRateLimiter
	NewCredentialRedactor       = agentmesh.NewCredentialRedactor
	NewMcpResponseScanner       = agentmesh.NewMcpResponseScanner
	NewMcpSecurityScanner       = agentmesh.NewMcpSecurityScanner
	NewMcpGateway               = agentmesh.NewMcpGateway
)
