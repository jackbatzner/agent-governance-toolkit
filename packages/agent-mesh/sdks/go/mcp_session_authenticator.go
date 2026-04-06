// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"fmt"
	"sync"
	"time"
)

// SessionStore persists MCP sessions.
type SessionStore interface {
	Save(session McpSession) error
	Get(token string) (*McpSession, error)
	Delete(token string) error
	DeleteExpired(now time.Time) error
	CountActive(agentID string, now time.Time) (int, error)
}

// InMemorySessionStore is the default thread-safe session store.
type InMemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]McpSession
}

// NewInMemorySessionStore creates an in-memory session store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]McpSession),
	}
}

// Save stores a session by token.
func (s *InMemorySessionStore) Save(session McpSession) error {
	if s == nil {
		return fmt.Errorf("%w: session store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]McpSession)
	}
	s.sessions[session.Token] = session
	return nil
}

// Get fetches a session by token.
func (s *InMemorySessionStore) Get(token string) (*McpSession, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: session store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok {
		return nil, nil
	}
	copy := session
	return &copy, nil
}

// Delete removes a session token.
func (s *InMemorySessionStore) Delete(token string) error {
	if s == nil {
		return fmt.Errorf("%w: session store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

// DeleteExpired removes expired sessions.
func (s *InMemorySessionStore) DeleteExpired(now time.Time) error {
	if s == nil {
		return fmt.Errorf("%w: session store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, token)
		}
	}
	return nil
}

// CountActive counts active sessions for an agent after expiring stale rows.
func (s *InMemorySessionStore) CountActive(agentID string, now time.Time) (int, error) {
	if s == nil {
		return 0, fmt.Errorf("%w: session store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, token)
			continue
		}
		if session.AgentID == agentID {
			count++
		}
	}
	return count, nil
}

// McpSessionAuthenticatorConfig configures session issuance and validation.
type McpSessionAuthenticatorConfig struct {
	Clock                 McpClock
	Store                 SessionStore
	SessionTTL            time.Duration
	MaxConcurrentSessions int
	MaxCreationsPerWindow int
	CreationWindow        time.Duration
	TokenGenerator        McpTokenGenerator
}

// McpSessionAuthenticator manages the MCP session lifecycle.
type McpSessionAuthenticator struct {
	mu                    sync.Mutex
	clock                 McpClock
	store                 SessionStore
	sessionTTL            time.Duration
	maxConcurrentSessions int
	tokenGenerator        McpTokenGenerator
	creationLimiter       *McpSlidingRateLimiter
}

// NewMcpSessionAuthenticator constructs a thread-safe authenticator.
func NewMcpSessionAuthenticator(config McpSessionAuthenticatorConfig) (*McpSessionAuthenticator, error) {
	if config.SessionTTL <= 0 {
		config.SessionTTL = defaultMcpSessionTTL
	}
	if config.MaxConcurrentSessions <= 0 {
		config.MaxConcurrentSessions = 5
	}
	if config.MaxCreationsPerWindow <= 0 {
		config.MaxCreationsPerWindow = defaultMcpMaxCreations
	}
	if config.CreationWindow <= 0 {
		config.CreationWindow = defaultMcpSessionWindow
	}
	if config.Store == nil {
		config.Store = NewInMemorySessionStore()
	}
	if config.TokenGenerator == nil {
		config.TokenGenerator = defaultMcpTokenGenerator(defaultMcpTokenBytes)
	}
	limiter, err := NewMcpSlidingRateLimiter(McpSlidingRateLimiterConfig{
		Clock:       config.Clock,
		Window:      config.CreationWindow,
		MaxRequests: config.MaxCreationsPerWindow,
	})
	if err != nil {
		return nil, err
	}
	return &McpSessionAuthenticator{
		clock:                 normalizeMcpClock(config.Clock),
		store:                 config.Store,
		sessionTTL:            config.SessionTTL,
		maxConcurrentSessions: config.MaxConcurrentSessions,
		tokenGenerator:        config.TokenGenerator,
		creationLimiter:       limiter,
	}, nil
}

// CreateSession issues a new crypto-random session after rate-limit and concurrency checks.
func (a *McpSessionAuthenticator) CreateSession(agentID string) (_ McpSession, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: session authenticator panic: %v", ErrMcpFailClosed, recovered)
		}
	}()
	if a == nil {
		return McpSession{}, fmt.Errorf("%w: authenticator is nil", ErrMcpFailClosed)
	}
	if agentID == "" {
		return McpSession{}, fmt.Errorf("%w: agent id is required", ErrMcpInvalidConfig)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clock()
	if err := a.store.DeleteExpired(now); err != nil {
		return McpSession{}, fmt.Errorf("%w: expiring sessions failed: %v", ErrMcpFailClosed, err)
	}
	if _, err := a.creationLimiter.Allow(agentID); err != nil {
		return McpSession{}, err
	}
	activeSessions, err := a.store.CountActive(agentID, now)
	if err != nil {
		return McpSession{}, fmt.Errorf("%w: counting sessions failed: %v", ErrMcpFailClosed, err)
	}
	if activeSessions >= a.maxConcurrentSessions {
		return McpSession{}, fmt.Errorf("%w: maximum concurrent sessions reached", ErrMcpSessionLimitExceeded)
	}
	token, err := a.tokenGenerator()
	if err != nil {
		return McpSession{}, fmt.Errorf("%w: generating session token: %v", ErrMcpFailClosed, err)
	}
	session := McpSession{
		Token:     token,
		AgentID:   agentID,
		CreatedAt: now,
		ExpiresAt: now.Add(a.sessionTTL),
	}
	if err := a.store.Save(session); err != nil {
		return McpSession{}, fmt.Errorf("%w: storing session failed: %v", ErrMcpFailClosed, err)
	}
	return session, nil
}

// ValidateSession verifies the token exists and has not expired.
func (a *McpSessionAuthenticator) ValidateSession(token string) (_ *McpSession, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: session authenticator panic: %v", ErrMcpFailClosed, recovered)
		}
	}()
	if a == nil {
		return nil, fmt.Errorf("%w: authenticator is nil", ErrMcpFailClosed)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrMcpInvalidConfig)
	}
	now := a.clock()
	if err := a.store.DeleteExpired(now); err != nil {
		return nil, fmt.Errorf("%w: expiring sessions failed: %v", ErrMcpFailClosed, err)
	}
	session, err := a.store.Get(token)
	if err != nil {
		return nil, fmt.Errorf("%w: reading session failed: %v", ErrMcpFailClosed, err)
	}
	if session == nil {
		return nil, ErrMcpSessionNotFound
	}
	if !session.ExpiresAt.After(now) {
		_ = a.store.Delete(token)
		return nil, ErrMcpSessionExpired
	}
	return session, nil
}

// RevokeSession removes an existing session token.
func (a *McpSessionAuthenticator) RevokeSession(token string) error {
	if a == nil {
		return fmt.Errorf("%w: authenticator is nil", ErrMcpFailClosed)
	}
	if token == "" {
		return fmt.Errorf("%w: token is required", ErrMcpInvalidConfig)
	}
	if err := a.store.Delete(token); err != nil {
		return fmt.Errorf("%w: deleting session failed: %v", ErrMcpFailClosed, err)
	}
	return nil
}
