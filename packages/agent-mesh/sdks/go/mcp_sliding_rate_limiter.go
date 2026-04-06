// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// RateLimitStore persists per-agent rate-limit buckets.
type RateLimitStore interface {
	CheckAndRecord(agentID string, now time.Time, window time.Duration, maxRequests int, inactiveTTL time.Duration) (McpRateLimitDecision, error)
}

type mcpRateLimitBucket struct {
	timestamps []time.Time
	lastSeen   time.Time
}

// InMemoryRateLimitStore is the default thread-safe sliding-window store.
type InMemoryRateLimitStore struct {
	mu      sync.Mutex
	buckets map[string]*mcpRateLimitBucket
}

// NewInMemoryRateLimitStore creates an in-memory rate-limit store.
func NewInMemoryRateLimitStore() *InMemoryRateLimitStore {
	return &InMemoryRateLimitStore{
		buckets: make(map[string]*mcpRateLimitBucket),
	}
}

// CheckAndRecord applies a sliding-window decision and evicts inactive buckets.
func (s *InMemoryRateLimitStore) CheckAndRecord(agentID string, now time.Time, window time.Duration, maxRequests int, inactiveTTL time.Duration) (McpRateLimitDecision, error) {
	if s == nil {
		return McpRateLimitDecision{}, fmt.Errorf("%w: rate-limit store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.buckets == nil {
		s.buckets = make(map[string]*mcpRateLimitBucket)
	}
	for key, bucket := range s.buckets {
		if now.Sub(bucket.lastSeen) > inactiveTTL {
			delete(s.buckets, key)
		}
	}

	bucket := s.buckets[agentID]
	if bucket == nil {
		bucket = &mcpRateLimitBucket{}
		s.buckets[agentID] = bucket
	}
	cutoff := now.Add(-window)
	trimmed := bucket.timestamps[:0]
	for _, ts := range bucket.timestamps {
		if !ts.Before(cutoff) {
			trimmed = append(trimmed, ts)
		}
	}
	bucket.timestamps = trimmed
	bucket.lastSeen = now
	if len(bucket.timestamps) >= maxRequests {
		retryAfter := time.Duration(0)
		if len(bucket.timestamps) > 0 {
			retryAfter = window - now.Sub(bucket.timestamps[0])
			if retryAfter < 0 {
				retryAfter = 0
			}
		}
		return McpRateLimitDecision{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: retryAfter,
		}, nil
	}
	bucket.timestamps = append(bucket.timestamps, now)
	return McpRateLimitDecision{
		Allowed:    true,
		Remaining:  maxRequests - len(bucket.timestamps),
		RetryAfter: 0,
	}, nil
}

// McpSlidingRateLimiterConfig configures an MCP sliding-window limiter.
type McpSlidingRateLimiterConfig struct {
	Clock       McpClock
	Store       RateLimitStore
	Window      time.Duration
	MaxRequests int
	InactiveTTL time.Duration
	Metrics     *McpMetrics
}

// McpSlidingRateLimiter enforces per-agent sliding-window rate limits.
type McpSlidingRateLimiter struct {
	clock       McpClock
	store       RateLimitStore
	window      time.Duration
	maxRequests int
	inactiveTTL time.Duration
	metrics     *McpMetrics
}

// NewMcpSlidingRateLimiter creates a new rate limiter with safe defaults.
func NewMcpSlidingRateLimiter(config McpSlidingRateLimiterConfig) (*McpSlidingRateLimiter, error) {
	if config.Window <= 0 {
		config.Window = time.Minute
	}
	if config.MaxRequests <= 0 {
		config.MaxRequests = defaultMcpMaxRequests
	}
	if config.InactiveTTL <= 0 {
		config.InactiveTTL = defaultMcpBucketIdleTTL
	}
	if config.Window <= 0 || config.MaxRequests <= 0 || config.InactiveTTL <= 0 {
		return nil, fmt.Errorf("%w: invalid rate limiter settings", ErrMcpInvalidConfig)
	}
	if config.Store == nil {
		config.Store = NewInMemoryRateLimitStore()
	}
	return &McpSlidingRateLimiter{
		clock:       normalizeMcpClock(config.Clock),
		store:       config.Store,
		window:      config.Window,
		maxRequests: config.MaxRequests,
		inactiveTTL: config.InactiveTTL,
		metrics:     config.Metrics,
	}, nil
}

// Allow checks and records a request for the supplied agent.
func (l *McpSlidingRateLimiter) Allow(agentID string) (decision McpRateLimitDecision, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			decision = McpRateLimitDecision{}
			err = fmt.Errorf("%w: rate limiter panic: %v", ErrMcpFailClosed, recovered)
		}
		if err != nil && errors.Is(err, ErrMcpFailClosed) {
			decision = McpRateLimitDecision{}
			decision.Allowed = false
			l.metrics.RecordRateLimit("fail_closed")
		}
	}()
	if l == nil {
		return McpRateLimitDecision{}, fmt.Errorf("%w: rate limiter is nil", ErrMcpFailClosed)
	}
	if agentID == "" {
		return McpRateLimitDecision{}, fmt.Errorf("%w: agent id is required", ErrMcpInvalidConfig)
	}
	decision, err = l.store.CheckAndRecord(agentID, l.clock(), l.window, l.maxRequests, l.inactiveTTL)
	if err != nil {
		return McpRateLimitDecision{}, fmt.Errorf("%w: rate limit store failed: %v", ErrMcpFailClosed, err)
	}
	if !decision.Allowed {
		l.metrics.RecordRateLimit("denied")
		return decision, fmt.Errorf("%w: retry after %s", ErrMcpRateLimited, decision.RetryAfter)
	}
	l.metrics.RecordRateLimit("allowed")
	return decision, nil
}

type errRateLimitStore struct {
	err error
}

func (s errRateLimitStore) CheckAndRecord(string, time.Time, time.Duration, int, time.Duration) (McpRateLimitDecision, error) {
	if s.err == nil {
		return McpRateLimitDecision{}, errors.New("forced rate-limit store failure")
	}
	return McpRateLimitDecision{}, s.err
}
