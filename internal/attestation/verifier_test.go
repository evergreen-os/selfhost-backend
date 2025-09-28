package attestation

import (
	"bytes"
	"testing"
	"time"
)

func TestNewVerifierValidatesTTL(t *testing.T) {
	if _, err := NewVerifier(0); err == nil {
		t.Fatal("expected error for non-positive ttl")
	}
}

func TestVerifyRequiresFields(t *testing.T) {
	verifier, _ := NewVerifier(time.Minute)
	if err := verifier.Verify(Quote{}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestVerifyNonceMismatch(t *testing.T) {
	verifier, _ := NewVerifier(time.Minute)
	quote := Quote{ExpectedNonce: "abc", Nonce: "xyz", Quote: []byte("payload"), Signature: []byte("payload"), ProducedAt: time.Now()}
	if err := verifier.Verify(quote); err == nil {
		t.Fatal("expected nonce mismatch error")
	}
}

func TestVerifySignatureMismatch(t *testing.T) {
	verifier, _ := NewVerifier(time.Minute)
	quote := Quote{ExpectedNonce: "abc", Nonce: "abc", Quote: []byte("payload"), Signature: []byte("nope"), ProducedAt: time.Now()}
	if err := verifier.Verify(quote); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestVerifyExpiredQuote(t *testing.T) {
	verifier, _ := NewVerifier(time.Minute)
	old := time.Now().Add(-2 * time.Minute)
	quote := Quote{ExpectedNonce: "abc", Nonce: "abc", Quote: []byte("payload"), Signature: []byte("payload"), ProducedAt: old}
	if err := verifier.Verify(quote); err == nil {
		t.Fatal("expected expiration error")
	}
}

func TestVerifySuccess(t *testing.T) {
	verifier, _ := NewVerifier(5 * time.Minute)
	now := time.Now()
	verifier.WithClock(func() time.Time { return now })
	payload := []byte("payload")
	quote := Quote{ExpectedNonce: "abc", Nonce: "abc", Quote: payload, Signature: payload, ProducedAt: now.Add(-time.Minute)}
	if err := verifier.Verify(quote); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Ensure secureCompare uses constant time semantics by verifying identical strings succeed
	if !secureCompare("constant", "constant") {
		t.Fatal("expected secureCompare to succeed for identical strings")
	}
	if secureCompare("constant", "different") {
		t.Fatal("expected secureCompare to fail for different strings")
	}
	if !bytes.Equal([]byte(fingerprint(payload)), []byte(fingerprint(payload))) {
		t.Fatal("expected deterministic fingerprint")
	}
}
