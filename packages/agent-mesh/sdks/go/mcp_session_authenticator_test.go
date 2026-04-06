// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"testing"
	"time"
)

type errSessionStore struct{}

func (errSessionStore) Save(McpSession) error           { return errors.New("save failed") }
func (errSessionStore) Get(string) (*McpSession, error) { return nil, errors.New("get failed") }
func (errSessionStore) Delete(string) error             { return errors.New("delete failed") }
func (errSessionStore) DeleteExpired(time.Time) error   { return errors.New("expire failed") }
func (errSessionStore) CountActive(string, time.Time) (int, error) {
	return 0, errors.New("count failed")
}

func TestMcpSessionAuthenticatorLifecycle(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	tokens := []string{"session-1"}
	authenticator, err := NewMcpSessionAuthenticator(McpSessionAuthenticatorConfig{
		Clock: func() time.Time { return now },
		TokenGenerator: func() (string, error) {
			token := tokens[0]
			tokens = tokens[1:]
			return token, nil
		},
	})
	if err != nil {
		t.Fatalf("NewMcpSessionAuthenticator: %v", err)
	}
	session, err := authenticator.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	validated, err := authenticator.ValidateSession(session.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated.AgentID != "agent-1" {
		t.Fatalf("AgentID = %q, want agent-1", validated.AgentID)
	}
	if err := authenticator.RevokeSession(session.Token); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := authenticator.ValidateSession(session.Token); !errors.Is(err, ErrMcpSessionNotFound) {
		t.Fatalf("expected missing session after revoke, got %v", err)
	}
}

func TestMcpSessionAuthenticatorEnforcesLimits(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	tokens := []string{"s1", "s2"}
	authenticator, err := NewMcpSessionAuthenticator(McpSessionAuthenticatorConfig{
		Clock:                 func() time.Time { return now },
		MaxConcurrentSessions: 1,
		TokenGenerator: func() (string, error) {
			token := tokens[0]
			tokens = tokens[1:]
			return token, nil
		},
	})
	if err != nil {
		t.Fatalf("NewMcpSessionAuthenticator: %v", err)
	}
	if _, err := authenticator.CreateSession("agent-1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := authenticator.CreateSession("agent-1"); !errors.Is(err, ErrMcpSessionLimitExceeded) {
		t.Fatalf("expected session limit error, got %v", err)
	}
}

func TestMcpSessionAuthenticatorExpiresSessionsAndRateLimitsCreation(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	authenticator, err := NewMcpSessionAuthenticator(McpSessionAuthenticatorConfig{
		Clock:                 func() time.Time { return now },
		SessionTTL:            2 * time.Second,
		MaxConcurrentSessions: 5,
		MaxCreationsPerWindow: 1,
		CreationWindow:        time.Minute,
		TokenGenerator: func() (string, error) {
			return "rate-limited", nil
		},
	})
	if err != nil {
		t.Fatalf("NewMcpSessionAuthenticator: %v", err)
	}
	session, err := authenticator.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := authenticator.CreateSession("agent-1"); !errors.Is(err, ErrMcpRateLimited) {
		t.Fatalf("expected creation rate limit, got %v", err)
	}
	now = now.Add(3 * time.Second)
	if _, err := authenticator.ValidateSession(session.Token); !errors.Is(err, ErrMcpSessionNotFound) {
		t.Fatalf("expected expired session to be deleted, got %v", err)
	}
}

func TestMcpSessionAuthenticatorFailsClosedOnStoreError(t *testing.T) {
	authenticator, err := NewMcpSessionAuthenticator(McpSessionAuthenticatorConfig{
		Store:          errSessionStore{},
		TokenGenerator: func() (string, error) { return "bad", nil },
	})
	if err != nil {
		t.Fatalf("NewMcpSessionAuthenticator: %v", err)
	}
	if _, err := authenticator.CreateSession("agent-1"); !errors.Is(err, ErrMcpFailClosed) {
		t.Fatalf("expected fail-closed error, got %v", err)
	}
}
