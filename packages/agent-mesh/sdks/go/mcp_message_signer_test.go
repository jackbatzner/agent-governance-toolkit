// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"testing"
	"time"
)

type signerNonceStoreFunc struct {
	reserve func(string, time.Time, time.Time) (bool, error)
	cleanup func(time.Time) error
}

func (s signerNonceStoreFunc) Reserve(nonce string, expiresAt, now time.Time) (bool, error) {
	return s.reserve(nonce, expiresAt, now)
}

func (s signerNonceStoreFunc) Cleanup(now time.Time) error {
	return s.cleanup(now)
}

func TestNewMcpMessageSignerRejectsShortKeys(t *testing.T) {
	_, err := NewMcpMessageSigner(McpMessageSignerConfig{Key: []byte("short")})
	if !errors.Is(err, ErrMcpInvalidConfig) {
		t.Fatalf("expected invalid config error, got %v", err)
	}
}

func TestMcpMessageSignerSignsAndVerifies(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	signer, err := NewMcpMessageSigner(McpMessageSignerConfig{
		Key:            []byte("0123456789abcdef0123456789abcdef"),
		Clock:          func() time.Time { return now },
		NonceGenerator: func() (string, error) { return "nonce-1", nil },
	})
	if err != nil {
		t.Fatalf("NewMcpMessageSigner: %v", err)
	}
	envelope, err := signer.Sign(McpSignedEnvelope{
		AgentID:  "agent-1",
		ToolName: "search",
		Payload:  map[string]any{"query": "owasp"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if envelope.Signature == "" || envelope.Nonce == "" || envelope.Timestamp.IsZero() {
		t.Fatal("signature metadata should be populated")
	}
	if err := signer.Verify(envelope); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestMcpMessageSignerRejectsReplayAndTampering(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	signer, err := NewMcpMessageSigner(McpMessageSignerConfig{
		Key:            []byte("0123456789abcdef0123456789abcdef"),
		Clock:          func() time.Time { return now },
		NonceGenerator: func() (string, error) { return "nonce-1", nil },
	})
	if err != nil {
		t.Fatalf("NewMcpMessageSigner: %v", err)
	}
	envelope, err := signer.Sign(McpSignedEnvelope{
		AgentID:  "agent-1",
		ToolName: "search",
		Payload:  map[string]any{"query": "owasp"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verify(envelope); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := signer.Verify(envelope); !errors.Is(err, ErrMcpReplayDetected) {
		t.Fatalf("expected replay error, got %v", err)
	}

	tampered := envelope
	tampered.Nonce = "nonce-2"
	tampered.Payload = map[string]any{"query": "tampered"}
	if err := signer.Verify(tampered); !errors.Is(err, ErrMcpInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestInMemorySignerNonceStoreEvictsLRUEntries(t *testing.T) {
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	store := NewInMemorySignerNonceStore(2)
	if reserved, _ := store.Reserve("n1", now.Add(time.Minute), now); !reserved {
		t.Fatal("expected n1 to be reserved")
	}
	if reserved, _ := store.Reserve("n2", now.Add(time.Minute), now); !reserved {
		t.Fatal("expected n2 to be reserved")
	}
	if reserved, _ := store.Reserve("n3", now.Add(time.Minute), now); !reserved {
		t.Fatal("expected n3 to be reserved")
	}
	if reserved, _ := store.Reserve("n1", now.Add(time.Minute), now); !reserved {
		t.Fatal("expected n1 to be evicted and reservable again")
	}
}

func TestMcpMessageSignerFailsClosedOnNonceStoreError(t *testing.T) {
	signer, err := NewMcpMessageSigner(McpMessageSignerConfig{
		Key:            []byte("0123456789abcdef0123456789abcdef"),
		Clock:          func() time.Time { return time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC) },
		NonceGenerator: func() (string, error) { return "nonce-1", nil },
		NonceStore: signerNonceStoreFunc{
			reserve: func(string, time.Time, time.Time) (bool, error) { return false, errors.New("boom") },
			cleanup: func(time.Time) error { return nil },
		},
	})
	if err != nil {
		t.Fatalf("NewMcpMessageSigner: %v", err)
	}
	envelope, err := signer.Sign(McpSignedEnvelope{Payload: "safe"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verify(envelope); !errors.Is(err, ErrMcpFailClosed) {
		t.Fatalf("expected fail-closed error, got %v", err)
	}
}
