package policies

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/config"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPolicyService(t *testing.T) {
	t.Run("PolicyServiceCreation", func(t *testing.T) {
		t.Run("NewPolicyService", func(t *testing.T) {
			// Test that NewPolicyService creates a service with Ed25519 keys
			service, err := NewPolicyService(nil, config.PolicyConfig{}) // Using nil DB for unit test
			if err != nil {
				t.Errorf("NewPolicyService failed: %v", err)
			}

			if service == nil {
				t.Error("Policy service should not be nil")
			}

			if len(service.signingKey) != ed25519.PrivateKeySize {
				t.Errorf("Signing key should be %d bytes, got %d", ed25519.PrivateKeySize, len(service.signingKey))
			}

			if len(service.verifyingKey) != ed25519.PublicKeySize {
				t.Errorf("Verifying key should be %d bytes, got %d", ed25519.PublicKeySize, len(service.verifyingKey))
			}

			if service.signingKeyID == "" {
				t.Error("Signing key ID should not be empty")
			}
		})

		t.Run("LoadsSigningKeyFromFile", func(t *testing.T) {
			dir := t.TempDir()
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			encoded := base64.StdEncoding.EncodeToString(privateKey)
			keyPath := filepath.Join(dir, "policy.key")
			if err := os.WriteFile(keyPath, []byte(encoded), 0o600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			service, err := NewPolicyService(nil, config.PolicyConfig{SigningKeyPath: keyPath, SigningKeyID: "custom-id"})
			if err != nil {
				t.Fatalf("NewPolicyService returned error: %v", err)
			}
			if service.signingKeyID != "custom-id" {
				t.Fatalf("expected signing key id to be custom-id, got %s", service.signingKeyID)
			}
			if !bytes.Equal(service.signingKey, privateKey) {
				t.Fatalf("expected signing key to match configured material")
			}
			if !bytes.Equal(service.verifyingKey, privateKey.Public().(ed25519.PublicKey)) {
				t.Fatalf("expected verifying key to match derived public key")
			}
		})
	})

	t.Run("PolicySigning", func(t *testing.T) {
		t.Run("SignPolicy", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:      "test-policy-1",
				Name:    "Test Policy",
				Version: timestamppb.New(time.Now()),
				Apps: &pb.AppPolicy{
					AutoInstallRequired:   true,
					AutoRemoveForbidden:   true,
					InstallTimeoutSeconds: 300,
				},
				Updates: &pb.UpdatePolicy{
					Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
					AutoInstall: true,
					AutoReboot:  false,
				},
				SigningKeyId: service.signingKeyID,
			}

			signature, err := service.signPolicy(policy)
			if err != nil {
				t.Errorf("Policy signing failed: %v", err)
			}

			if signature == "" {
				t.Error("Signature should not be empty")
			}

			// Verify signature is valid base64
			_, err = base64.StdEncoding.DecodeString(signature)
			if err != nil {
				t.Errorf("Signature should be valid base64: %v", err)
			}
		})

		t.Run("VerifyPolicySignature", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:      "test-policy-2",
				Name:    "Test Policy 2",
				Version: timestamppb.New(time.Now()),
				Apps: &pb.AppPolicy{
					AutoInstallRequired:   true,
					AutoRemoveForbidden:   false,
					InstallTimeoutSeconds: 600,
				},
				SigningKeyId: service.signingKeyID,
			}

			// Sign the policy
			signature, err := service.signPolicy(policy)
			if err != nil {
				t.Fatalf("Policy signing failed: %v", err)
			}

			// Set signature on policy
			policy.Signature = signature

			// Verify signature
			err = service.verifyPolicySignature(policy)
			if err != nil {
				t.Errorf("Policy signature verification failed: %v", err)
			}
		})

		t.Run("VerifyInvalidSignature", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:           "test-policy-3",
				Name:         "Test Policy 3",
				Version:      timestamppb.New(time.Now()),
				SigningKeyId: service.signingKeyID,
				Signature:    "invalid-signature",
			}

			// Verification should fail
			err = service.verifyPolicySignature(policy)
			if err == nil {
				t.Error("Expected signature verification to fail for invalid signature")
			}
		})

		t.Run("VerifyMissingSignature", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:           "test-policy-4",
				Name:         "Test Policy 4",
				Version:      timestamppb.New(time.Now()),
				SigningKeyId: service.signingKeyID,
				// Signature is missing
			}

			// Verification should fail
			err = service.verifyPolicySignature(policy)
			if err == nil {
				t.Error("Expected signature verification to fail for missing signature")
			}
		})

		t.Run("VerifyWrongKeyID", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:           "test-policy-5",
				Name:         "Test Policy 5",
				Version:      timestamppb.New(time.Now()),
				SigningKeyId: "wrong-key-id",
				Signature:    "some-signature",
			}

			// Verification should fail
			err = service.verifyPolicySignature(policy)
			if err == nil {
				t.Error("Expected signature verification to fail for wrong key ID")
			}
		})
	})

	t.Run("PolicySerialization", func(t *testing.T) {
		t.Run("PolicyToJSON", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:      "json-test-policy",
				Name:    "JSON Test Policy",
				Version: timestamppb.New(time.Now()),
				Apps: &pb.AppPolicy{
					Packages: []*pb.AppPackage{
						{
							FlatpakRef:  "org.mozilla.firefox",
							Requirement: pb.AppRequirement_APP_REQUIREMENT_REQUIRED,
							DisplayName: "Firefox",
						},
					},
					AutoInstallRequired:   true,
					InstallTimeoutSeconds: 300,
				},
				Updates: &pb.UpdatePolicy{
					Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
					AutoInstall: true,
				},
			}

			jsonStr, err := service.policyToJSON(policy)
			if err != nil {
				t.Errorf("Policy to JSON conversion failed: %v", err)
			}

			if jsonStr == "" {
				t.Error("JSON string should not be empty")
			}

			// Should contain key fields
			if !containsString(jsonStr, policy.Id) {
				t.Error("JSON should contain policy ID")
			}

			if !containsString(jsonStr, policy.Name) {
				t.Error("JSON should contain policy name")
			}
		})

		t.Run("JSONToPolicy", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			originalPolicy := &pb.PolicyBundle{
				Id:      "roundtrip-test",
				Name:    "Roundtrip Test Policy",
				Version: timestamppb.New(time.Now()),
				Security: &pb.SecurityPolicy{
					SelinuxEnforcing:         true,
					RequireScreenLock:        true,
					ScreenLockTimeoutSeconds: 300,
				},
			}

			// Convert to JSON
			jsonStr, err := service.policyToJSON(originalPolicy)
			if err != nil {
				t.Fatalf("Policy to JSON failed: %v", err)
			}

			// Convert back to policy
			recoveredPolicy, err := service.jsonToPolicy(jsonStr)
			if err != nil {
				t.Errorf("JSON to policy conversion failed: %v", err)
			}

			// Verify key fields match
			if recoveredPolicy.Id != originalPolicy.Id {
				t.Errorf("Policy ID mismatch: expected %s, got %s", originalPolicy.Id, recoveredPolicy.Id)
			}

			if recoveredPolicy.Name != originalPolicy.Name {
				t.Errorf("Policy name mismatch: expected %s, got %s", originalPolicy.Name, recoveredPolicy.Name)
			}

			if recoveredPolicy.Security == nil {
				t.Error("Security policy should not be nil after roundtrip")
			} else {
				if recoveredPolicy.Security.SelinuxEnforcing != originalPolicy.Security.SelinuxEnforcing {
					t.Error("SELinux enforcing setting should match after roundtrip")
				}
			}
		})

		t.Run("InvalidJSON", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			invalidJSON := `{"invalid": json}`

			_, err = service.jsonToPolicy(invalidJSON)
			if err == nil {
				t.Error("Expected JSON parsing to fail for invalid JSON")
			}
		})
	})

	t.Run("DefaultPolicy", func(t *testing.T) {
		t.Run("GetDefaultPolicy", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			defaultPolicy := service.GetDefaultPolicy()

			if defaultPolicy == nil {
				t.Error("Default policy should not be nil")
			}

			if defaultPolicy.Id != "default-policy" {
				t.Errorf("Expected default policy ID 'default-policy', got %s", defaultPolicy.Id)
			}

			if defaultPolicy.Name != "Default Policy" {
				t.Errorf("Expected default policy name 'Default Policy', got %s", defaultPolicy.Name)
			}

			if defaultPolicy.Apps == nil {
				t.Error("Default policy should have app policy")
			}

			if defaultPolicy.Updates == nil {
				t.Error("Default policy should have update policy")
			}

			if defaultPolicy.Security == nil {
				t.Error("Default policy should have security policy")
			}

			if defaultPolicy.SigningKeyId != service.signingKeyID {
				t.Error("Default policy should have correct signing key ID")
			}
		})
	})

	t.Run("SignatureIntegrity", func(t *testing.T) {
		t.Run("PolicyModificationDetection", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:      "integrity-test",
				Name:    "Integrity Test Policy",
				Version: timestamppb.New(time.Now()),
				Apps: &pb.AppPolicy{
					AutoInstallRequired: true,
				},
				SigningKeyId: service.signingKeyID,
			}

			// Sign the policy
			signature, err := service.signPolicy(policy)
			if err != nil {
				t.Fatalf("Policy signing failed: %v", err)
			}
			policy.Signature = signature

			// Verify original signature works
			err = service.verifyPolicySignature(policy)
			if err != nil {
				t.Fatalf("Original policy signature verification failed: %v", err)
			}

			// Modify the policy after signing
			policy.Apps.AutoInstallRequired = false

			// Signature verification should now fail
			err = service.verifyPolicySignature(policy)
			if err == nil {
				t.Error("Expected signature verification to fail after policy modification")
			}
		})

		t.Run("SignatureDeterministic", func(t *testing.T) {
			service, err := NewPolicyService(nil, config.PolicyConfig{})
			if err != nil {
				t.Fatalf("Failed to create policy service: %v", err)
			}

			policy := &pb.PolicyBundle{
				Id:      "deterministic-test",
				Name:    "Deterministic Test Policy",
				Version: timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
				Updates: &pb.UpdatePolicy{
					Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
					AutoInstall: true,
				},
				SigningKeyId: service.signingKeyID,
			}

			// Sign the same policy multiple times
			sig1, err := service.signPolicy(policy)
			if err != nil {
				t.Fatalf("First signing failed: %v", err)
			}

			sig2, err := service.signPolicy(policy)
			if err != nil {
				t.Fatalf("Second signing failed: %v", err)
			}

			// Signatures should be identical for identical policy content
			if sig1 != sig2 {
				t.Error("Signatures should be deterministic for identical policy content")
			}
		})
	})
}

// Helper function to check if a string contains a substring
func containsString(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		haystack != needle &&
		findString(haystack, needle) >= 0
}

// Simple string search function
func findString(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
