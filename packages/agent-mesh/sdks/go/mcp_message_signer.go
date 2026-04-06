// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// SignerNonceStore persists nonces for replay protection.
type SignerNonceStore interface {
	Reserve(nonce string, expiresAt, now time.Time) (bool, error)
	Cleanup(now time.Time) error
}

type mcpNonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// InMemorySignerNonceStore is the default bounded LRU nonce store.
type InMemorySignerNonceStore struct {
	mu         sync.Mutex
	maxEntries int
	lru        *list.List
	index      map[string]*list.Element
}

// NewInMemorySignerNonceStore creates a bounded nonce store.
func NewInMemorySignerNonceStore(maxEntries int) *InMemorySignerNonceStore {
	if maxEntries <= 0 {
		maxEntries = defaultMcpNonceCacheSize
	}
	return &InMemorySignerNonceStore{
		maxEntries: maxEntries,
		lru:        list.New(),
		index:      make(map[string]*list.Element),
	}
}

// Reserve stores a nonce if it has not already been observed.
func (s *InMemorySignerNonceStore) Reserve(nonce string, expiresAt, now time.Time) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("%w: nonce store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(now)
	if existing, ok := s.index[nonce]; ok {
		entry := existing.Value.(mcpNonceEntry)
		if now.Before(entry.expiresAt) || now.Equal(entry.expiresAt) {
			s.lru.MoveToFront(existing)
			return false, nil
		}
		s.lru.Remove(existing)
		delete(s.index, nonce)
	}
	element := s.lru.PushFront(mcpNonceEntry{nonce: nonce, expiresAt: expiresAt})
	s.index[nonce] = element
	for s.lru.Len() > s.maxEntries {
		tail := s.lru.Back()
		if tail == nil {
			break
		}
		entry := tail.Value.(mcpNonceEntry)
		delete(s.index, entry.nonce)
		s.lru.Remove(tail)
	}
	return true, nil
}

// Cleanup removes expired nonce entries.
func (s *InMemorySignerNonceStore) Cleanup(now time.Time) error {
	if s == nil {
		return fmt.Errorf("%w: nonce store is nil", ErrMcpFailClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	return nil
}

func (s *InMemorySignerNonceStore) cleanupLocked(now time.Time) {
	for element := s.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(mcpNonceEntry)
		if now.Before(entry.expiresAt) {
			element = previous
			continue
		}
		delete(s.index, entry.nonce)
		s.lru.Remove(element)
		element = previous
	}
}

// McpMessageSignerConfig configures message signing and replay protection.
type McpMessageSignerConfig struct {
	Key                []byte
	Clock              McpClock
	NonceGenerator     McpTokenGenerator
	NonceStore         SignerNonceStore
	NonceTTL           time.Duration
	TimestampTolerance time.Duration
}

// McpMessageSigner signs and verifies MCP envelopes using HMAC-SHA256.
type McpMessageSigner struct {
	key                []byte
	clock              McpClock
	nonceGenerator     McpTokenGenerator
	nonceStore         SignerNonceStore
	nonceTTL           time.Duration
	timestampTolerance time.Duration
}

// NewMcpMessageSigner constructs a signer with a 32-byte minimum HMAC key.
func NewMcpMessageSigner(config McpMessageSignerConfig) (*McpMessageSigner, error) {
	if len(config.Key) < 32 {
		return nil, fmt.Errorf("%w: HMAC keys must be at least 32 bytes", ErrMcpInvalidConfig)
	}
	if config.NonceTTL <= 0 {
		config.NonceTTL = defaultMcpNonceTTL
	}
	if config.TimestampTolerance <= 0 {
		config.TimestampTolerance = defaultMcpTimestampSkew
	}
	if config.NonceStore == nil {
		config.NonceStore = NewInMemorySignerNonceStore(defaultMcpNonceCacheSize)
	}
	if config.NonceGenerator == nil {
		config.NonceGenerator = defaultMcpTokenGenerator(defaultMcpNonceBytes)
	}
	return &McpMessageSigner{
		key:                append([]byte(nil), config.Key...),
		clock:              normalizeMcpClock(config.Clock),
		nonceGenerator:     config.NonceGenerator,
		nonceStore:         config.NonceStore,
		nonceTTL:           config.NonceTTL,
		timestampTolerance: config.TimestampTolerance,
	}, nil
}

// Sign stamps and signs an MCP envelope.
func (s *McpMessageSigner) Sign(envelope McpSignedEnvelope) (McpSignedEnvelope, error) {
	if s == nil {
		return McpSignedEnvelope{}, fmt.Errorf("%w: signer is nil", ErrMcpFailClosed)
	}
	timestamp := s.clock()
	nonce, err := s.nonceGenerator()
	if err != nil {
		return McpSignedEnvelope{}, fmt.Errorf("%w: generating nonce: %v", ErrMcpFailClosed, err)
	}
	envelope.Timestamp = timestamp
	envelope.Nonce = nonce
	envelope.Signature = ""
	signature, err := s.computeSignature(envelope)
	if err != nil {
		return McpSignedEnvelope{}, err
	}
	envelope.Signature = signature
	return envelope, nil
}

// Verify validates the signature, timestamp, and replay nonce. Any failure denies.
func (s *McpMessageSigner) Verify(envelope McpSignedEnvelope) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: signer panic: %v", ErrMcpFailClosed, recovered)
		}
	}()
	if s == nil {
		return fmt.Errorf("%w: signer is nil", ErrMcpFailClosed)
	}
	if envelope.Nonce == "" || envelope.Signature == "" || envelope.Timestamp.IsZero() {
		return fmt.Errorf("%w: missing signature metadata", ErrMcpInvalidSignature)
	}
	now := s.clock()
	if err := s.nonceStore.Cleanup(now); err != nil {
		return fmt.Errorf("%w: nonce cleanup failed: %v", ErrMcpFailClosed, err)
	}
	if durationAbs(now.Sub(envelope.Timestamp)) > s.timestampTolerance {
		return fmt.Errorf("%w: timestamp outside tolerance", ErrMcpInvalidSignature)
	}
	expected, err := s.computeSignature(McpSignedEnvelope{
		AgentID:   envelope.AgentID,
		ToolName:  envelope.ToolName,
		Payload:   envelope.Payload,
		Timestamp: envelope.Timestamp,
		Nonce:     envelope.Nonce,
	})
	if err != nil {
		return err
	}
	provided, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("%w: decoding provided signature", ErrMcpInvalidSignature)
	}
	expectedBytes, err := base64.RawURLEncoding.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("%w: decoding expected signature", ErrMcpFailClosed)
	}
	if !hmac.Equal(provided, expectedBytes) {
		return fmt.Errorf("%w: signature mismatch", ErrMcpInvalidSignature)
	}
	reserved, err := s.nonceStore.Reserve(envelope.Nonce, now.Add(s.nonceTTL), now)
	if err != nil {
		return fmt.Errorf("%w: nonce reserve failed: %v", ErrMcpFailClosed, err)
	}
	if !reserved {
		return fmt.Errorf("%w: nonce already used", ErrMcpReplayDetected)
	}
	return nil
}

func (s *McpMessageSigner) computeSignature(envelope McpSignedEnvelope) (string, error) {
	payload, err := canonicalMcpJSON(envelope.Payload)
	if err != nil {
		return "", fmt.Errorf("%w: canonical payload encoding failed: %v", ErrMcpFailClosed, err)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(envelope.AgentID))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(envelope.ToolName))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(envelope.Timestamp.UTC().Format(time.RFC3339Nano)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(envelope.Nonce))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func durationAbs(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
