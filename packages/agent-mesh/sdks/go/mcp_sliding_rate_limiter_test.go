// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"testing"
	"time"
)

func TestMcpSlidingRateLimiterAllowsAndRecovers(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	limiter, err := NewMcpSlidingRateLimiter(McpSlidingRateLimiterConfig{
		Clock:       func() time.Time { return now },
		MaxRequests: 2,
		Window:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMcpSlidingRateLimiter: %v", err)
	}
	if _, err := limiter.Allow("agent-1"); err != nil {
		t.Fatalf("first Allow: %v", err)
	}
	if _, err := limiter.Allow("agent-1"); err != nil {
		t.Fatalf("second Allow: %v", err)
	}
	if decision, err := limiter.Allow("agent-1"); !errors.Is(err, ErrMcpRateLimited) || decision.RetryAfter <= 0 {
		t.Fatalf("expected rate limit with retry after, got decision=%+v err=%v", decision, err)
	}
	now = now.Add(11 * time.Second)
	if _, err := limiter.Allow("agent-1"); err != nil {
		t.Fatalf("Allow after window: %v", err)
	}
}

func TestMcpSlidingRateLimiterEvictsInactiveBuckets(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryRateLimitStore()
	limiter, err := NewMcpSlidingRateLimiter(McpSlidingRateLimiterConfig{
		Clock:       func() time.Time { return now },
		Store:       store,
		MaxRequests: 5,
		Window:      time.Minute,
		InactiveTTL: time.Second,
	})
	if err != nil {
		t.Fatalf("NewMcpSlidingRateLimiter: %v", err)
	}
	if _, err := limiter.Allow("agent-a"); err != nil {
		t.Fatalf("Allow agent-a: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := limiter.Allow("agent-b"); err != nil {
		t.Fatalf("Allow agent-b: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.buckets) != 1 {
		t.Fatalf("bucket count = %d, want 1 after eviction", len(store.buckets))
	}
	if _, ok := store.buckets["agent-b"]; !ok {
		t.Fatal("expected only agent-b bucket to remain")
	}
}

func TestMcpSlidingRateLimiterFailsClosedOnStoreError(t *testing.T) {
	limiter, err := NewMcpSlidingRateLimiter(McpSlidingRateLimiterConfig{
		Store: errRateLimitStore{},
	})
	if err != nil {
		t.Fatalf("NewMcpSlidingRateLimiter: %v", err)
	}
	if _, err := limiter.Allow("agent-1"); !errors.Is(err, ErrMcpFailClosed) {
		t.Fatalf("expected fail-closed error, got %v", err)
	}
}
