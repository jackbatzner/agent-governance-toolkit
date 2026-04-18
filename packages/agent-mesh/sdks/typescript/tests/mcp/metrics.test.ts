// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  McpMetricsCollector,
  McpDecisionLabel,
  McpThreatLabel,
  McpScanLabel,
} from '../../src/mcp/metrics';

describe('McpMetricsCollector', () => {
  let collector: McpMetricsCollector;

  beforeEach(() => {
    collector = new McpMetricsCollector();
  });

  // ── snapshot starts empty ──

  it('returns zeroed snapshot initially', () => {
    const snap = collector.getSnapshot();
    expect(snap.decisions).toEqual({});
    expect(snap.threats_detected).toEqual({});
    expect(snap.rate_limit_hits).toBe(0);
    expect(snap.scans).toEqual({});
  });

  // ── recordDecision ──

  it('counts gateway decisions by label', () => {
    collector.recordDecision(McpDecisionLabel.Allowed);
    collector.recordDecision(McpDecisionLabel.Allowed);
    collector.recordDecision(McpDecisionLabel.Denied);

    const snap = collector.getSnapshot();
    expect(snap.decisions[McpDecisionLabel.Allowed]).toBe(2);
    expect(snap.decisions[McpDecisionLabel.Denied]).toBe(1);
  });

  // ── recordThreatsDetected ──

  it('accumulates threat counts by label', () => {
    collector.recordThreatsDetected(3, McpThreatLabel.ToolPoisoning);
    collector.recordThreatsDetected(1, McpThreatLabel.ToolPoisoning);
    collector.recordThreatsDetected(2, McpThreatLabel.CredentialLeak);

    const snap = collector.getSnapshot();
    expect(snap.threats_detected[McpThreatLabel.ToolPoisoning]).toBe(4);
    expect(snap.threats_detected[McpThreatLabel.CredentialLeak]).toBe(2);
  });

  it('handles zero-count threat recording', () => {
    collector.recordThreatsDetected(0, McpThreatLabel.Typosquatting);
    const snap = collector.getSnapshot();
    expect(snap.threats_detected[McpThreatLabel.Typosquatting]).toBe(0);
  });

  // ── recordRateLimitHit ──

  it('increments rate-limit hit counter', () => {
    collector.recordRateLimitHit();
    collector.recordRateLimitHit();
    collector.recordRateLimitHit();

    expect(collector.getSnapshot().rate_limit_hits).toBe(3);
  });

  // ── recordScan ──

  it('counts scans by label', () => {
    collector.recordScan(McpScanLabel.Response);
    collector.recordScan(McpScanLabel.ToolMetadata);
    collector.recordScan(McpScanLabel.Response);

    const snap = collector.getSnapshot();
    expect(snap.scans[McpScanLabel.Response]).toBe(2);
    expect(snap.scans[McpScanLabel.ToolMetadata]).toBe(1);
  });

  // ── reset ──

  it('clears all counters on reset', () => {
    collector.recordDecision(McpDecisionLabel.Allowed);
    collector.recordThreatsDetected(5, McpThreatLabel.RugPull);
    collector.recordRateLimitHit();
    collector.recordScan(McpScanLabel.Gateway);

    collector.reset();

    const snap = collector.getSnapshot();
    expect(snap.decisions).toEqual({});
    expect(snap.threats_detected).toEqual({});
    expect(snap.rate_limit_hits).toBe(0);
    expect(snap.scans).toEqual({});
  });

  // ── combined usage ──

  it('tracks all metric types independently', () => {
    collector.recordDecision(McpDecisionLabel.RateLimited);
    collector.recordThreatsDetected(1, McpThreatLabel.HiddenInstruction);
    collector.recordRateLimitHit();
    collector.recordScan(McpScanLabel.Gateway);

    const snap = collector.getSnapshot();
    expect(snap.decisions[McpDecisionLabel.RateLimited]).toBe(1);
    expect(snap.threats_detected[McpThreatLabel.HiddenInstruction]).toBe(1);
    expect(snap.rate_limit_hits).toBe(1);
    expect(snap.scans[McpScanLabel.Gateway]).toBe(1);
  });
});
