package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Quote represents a TPM attestation quote submitted by a device agent.
type Quote struct {
	Nonce         string
	Quote         []byte
	Signature     []byte
	ExpectedNonce string
	ProducedAt    time.Time
}

// Verifier validates TPM quotes using a shared nonce and signature fingerprint.
type Verifier struct {
	now func() time.Time
	ttl time.Duration
}

// NewVerifier constructs a Verifier with the provided freshness window.
func NewVerifier(ttl time.Duration) (*Verifier, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("ttl must be positive")
	}
	return &Verifier{now: time.Now, ttl: ttl}, nil
}

// WithClock overrides the verification clock for deterministic tests.
func (v *Verifier) WithClock(now func() time.Time) {
	if now != nil {
		v.now = now
	}
}

// Verify ensures the provided quote matches the expected nonce and is fresh.
func (v *Verifier) Verify(q Quote) error {
	if q.ExpectedNonce == "" {
		return fmt.Errorf("expected nonce required")
	}
	if q.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if !secureCompare(q.Nonce, q.ExpectedNonce) {
		return fmt.Errorf("nonce mismatch")
	}
	if len(q.Quote) == 0 {
		return fmt.Errorf("quote payload is required")
	}
	if len(q.Signature) == 0 {
		return fmt.Errorf("signature is required")
	}
	now := v.now().UTC()
	if q.ProducedAt.IsZero() {
		return fmt.Errorf("produced at timestamp required")
	}
	if now.Sub(q.ProducedAt.UTC()) > v.ttl {
		return fmt.Errorf("quote expired")
	}
	expectedFingerprint := fingerprint(q.Quote)
	actualFingerprint := fingerprint(q.Signature)
	if expectedFingerprint != actualFingerprint {
		return fmt.Errorf("quote signature mismatch")
	}
	return nil
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}

func fingerprint(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

var (
	// ErrQuoteVerification indicates attestation failed.
	ErrQuoteVerification = errors.New("attestation quote verification failed")
)
