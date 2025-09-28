package auth

import (
	"encoding/base64"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	secret := []byte("abcdefghijklmnopqrstuvwxyz123456")
	mgr, err := NewManager(secret, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	mgr.WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	mgr.WithBcryptCost(4)
	return mgr
}

func TestAdminTokenLifecycle(t *testing.T) {
	mgr := newTestManager(t)

	token, err := mgr.IssueAdminToken("user-123", "tenant-456", "owner")
	if err != nil {
		t.Fatalf("IssueAdminToken error: %v", err)
	}
	if token == "" {
		t.Fatal("expected token to be generated")
	}

	claims, err := mgr.ParseAdminToken(token)
	if err != nil {
		t.Fatalf("ParseAdminToken error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}
	if claims.TenantID != "tenant-456" {
		t.Fatalf("unexpected tenant id: %s", claims.TenantID)
	}
	if claims.Role != "owner" {
		t.Fatalf("unexpected role: %s", claims.Role)
	}
	if !claims.IssuedAt.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("unexpected issued at: %v", claims.IssuedAt)
	}
	if !claims.ExpiresAt.Equal(time.Unix(1700000000+3600, 0).UTC()) {
		t.Fatalf("unexpected expires at: %v", claims.ExpiresAt)
	}

	if _, err := mgr.ParseAdminToken(token + "corrupted"); err == nil {
		t.Fatal("expected signature validation error for corrupted token")
	}
}

func TestDeviceTokenLifecycle(t *testing.T) {
	mgr := newTestManager(t)

	token, hashed, err := mgr.IssueDeviceToken("device-abc", "tenant-xyz")
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}
	if token == "" || hashed == "" {
		t.Fatalf("expected non-empty token and hash")
	}

	claims, err := mgr.VerifyDeviceToken(token, "device-abc", "tenant-xyz", hashed)
	if err != nil {
		t.Fatalf("VerifyDeviceToken error: %v", err)
	}
	if claims.DeviceID != "device-abc" {
		t.Fatalf("unexpected device id: %s", claims.DeviceID)
	}
	if claims.TenantID != "tenant-xyz" {
		t.Fatalf("unexpected tenant id: %s", claims.TenantID)
	}

	if _, err := mgr.VerifyDeviceToken(token, "device-wrong", "tenant-xyz", hashed); err == nil {
		t.Fatal("expected mismatch error for wrong device id")
	}

	// Expired token check
	mgr.WithClock(func() time.Time { return time.Unix(1700000000+int64(3*time.Hour/time.Second), 0) })
	if _, err := mgr.VerifyDeviceToken(token, "device-abc", "tenant-xyz", hashed); err == nil {
		t.Fatal("expected expiry error when clock advanced")
	}
}

func TestPasswordHashing(t *testing.T) {
	mgr := newTestManager(t)

	hash, err := mgr.HashPassword("Secur3Pass!")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if err := mgr.CheckPassword("Secur3Pass!", hash); err != nil {
		t.Fatalf("CheckPassword error: %v", err)
	}
	if err := mgr.CheckPassword("WrongPass", hash); err == nil {
		t.Fatal("expected mismatch error for wrong password")
	}
}

func TestDeriveTokenFingerprintDeterministic(t *testing.T) {
	token := "sample.token.value"
	fp1 := DeriveTokenFingerprint(token)
	fp2 := DeriveTokenFingerprint(token)
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %s vs %s", fp1, fp2)
	}
	if _, err := base64.RawURLEncoding.DecodeString(fp1); err != nil {
		t.Fatalf("fingerprint not base64url: %v", err)
	}
}
