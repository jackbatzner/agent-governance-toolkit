// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "sync"

const (
	// McpMetricDecisions is the OpenTelemetry-style metric name for gateway decisions.
	McpMetricDecisions = "agentmesh.mcp.decisions"
	// McpMetricRateLimits is the OpenTelemetry-style metric name for rate-limit outcomes.
	McpMetricRateLimits = "agentmesh.mcp.rate_limits"
	// McpMetricScans is the OpenTelemetry-style metric name for MCP scanning results.
	McpMetricScans = "agentmesh.mcp.scans"
	// McpMetricThreats is the OpenTelemetry-style metric name for detected threats.
	McpMetricThreats = "agentmesh.mcp.threats"
)

// McpMetricsSnapshot exposes categorical metric counters for tests and exporters.
type McpMetricsSnapshot struct {
	Decisions  map[string]int64 `json:"decisions"`
	RateLimits map[string]int64 `json:"rate_limits"`
	Scans      map[string]int64 `json:"scans"`
	Threats    map[string]int64 `json:"threats"`
}

// McpMetrics stores OTel-aligned counters without forcing a metrics dependency.
type McpMetrics struct {
	mu         sync.Mutex
	decisions  map[string]int64
	rateLimits map[string]int64
	scans      map[string]int64
	threats    map[string]int64
}

// NewMcpMetrics creates a thread-safe categorical metric recorder.
func NewMcpMetrics() *McpMetrics {
	return &McpMetrics{
		decisions:  make(map[string]int64),
		rateLimits: make(map[string]int64),
		scans:      make(map[string]int64),
		threats:    make(map[string]int64),
	}
}

// RecordDecision records a gateway or enforcement decision.
func (m *McpMetrics) RecordDecision(decision PolicyDecision) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[string(decision)]++
}

// RecordRateLimit records a rate-limit outcome label.
func (m *McpMetrics) RecordRateLimit(label string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimits[label]++
}

// RecordScan records a scan label such as tool_metadata or response.
func (m *McpMetrics) RecordScan(label string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scans[label]++
}

// RecordThreat records a threat type label.
func (m *McpMetrics) RecordThreat(threatType McpThreatType) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threats[string(threatType)]++
}

// Snapshot returns a safe copy of all metric counters.
func (m *McpMetrics) Snapshot() McpMetricsSnapshot {
	if m == nil {
		return McpMetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return McpMetricsSnapshot{
		Decisions:  copyMcpMetricMap(m.decisions),
		RateLimits: copyMcpMetricMap(m.rateLimits),
		Scans:      copyMcpMetricMap(m.scans),
		Threats:    copyMcpMetricMap(m.threats),
	}
}

func copyMcpMetricMap(source map[string]int64) map[string]int64 {
	clone := make(map[string]int64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
