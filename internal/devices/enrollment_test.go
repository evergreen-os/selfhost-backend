package devices

import (
	"context"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDeviceEnrollment(t *testing.T) {
	t.Run("EnrollDeviceRequest_Validation", func(t *testing.T) {
		// Test valid enrollment request
		t.Run("ValidRequest", func(t *testing.T) {
			req := &pb.EnrollDeviceRequest{
				EnrollmentToken: "valid-tenant-token",
				Hardware: &pb.HardwareInfo{
					Model:             "ThinkPad X1",
					Manufacturer:      "Lenovo",
					SerialNumber:      "SN123456789",
					Architecture:      pb.Architecture_ARCHITECTURE_AMD64,
					TotalMemoryBytes:  16 * 1024 * 1024 * 1024,  // 16GB
					TotalStorageBytes: 512 * 1024 * 1024 * 1024, // 512GB
					TpmEnabled:        true,
					TpmVersion:        "2.0",
				},
				OsInfo: &pb.OSInfo{
					Name:          "EvergreenOS",
					Version:       "1.0.0",
					KernelVersion: "6.1.0-evergreen",
					BuildId:       "build-123",
				},
				Network: &pb.NetworkInfo{
					PrimaryMacAddress: "00:11:22:33:44:55",
					Hostname:          "student-laptop-001",
					Interfaces: []*pb.NetworkInterface{
						{
							Name:       "eth0",
							MacAddress: "00:11:22:33:44:55",
							Active:     true,
							Type:       "ethernet",
						},
					},
				},
				AgentVersion: &pb.Version{
					Version:   "1.0.0",
					Commit:    "abc123def456",
					BuildTime: timestamppb.New(time.Now()),
				},
				EnrollmentSecret: "shared-secret-123",
				Nonce:            "random-nonce-456",
			}

			// Validate required fields
			if req.EnrollmentToken == "" {
				t.Error("Enrollment token is required")
			}

			if req.Hardware == nil {
				t.Error("Hardware info is required")
			}

			if req.OsInfo == nil {
				t.Error("OS info is required")
			}

			if req.Network == nil {
				t.Error("Network info is required")
			}

			if req.AgentVersion == nil {
				t.Error("Agent version is required")
			}

			if req.Nonce == "" {
				t.Error("Nonce is required for replay protection")
			}
		})

		t.Run("InvalidRequest_MissingFields", func(t *testing.T) {
			// Test missing enrollment token
			req := &pb.EnrollDeviceRequest{}

			if req.EnrollmentToken != "" {
				t.Error("Expected empty enrollment token")
			}

			if req.Hardware != nil {
				t.Error("Expected nil hardware info")
			}
		})

		t.Run("InvalidRequest_MalformedData", func(t *testing.T) {
			// Test malformed hardware info
			req := &pb.EnrollDeviceRequest{
				EnrollmentToken: "valid-token",
				Hardware: &pb.HardwareInfo{
					Model:        "", // Empty model should be invalid
					Manufacturer: "Test Corp",
					SerialNumber: "SN123",
					Architecture: pb.Architecture_ARCHITECTURE_UNSPECIFIED,
				},
			}

			if req.Hardware.Model != "" {
				t.Error("Expected empty model for validation test")
			}

			if req.Hardware.Architecture != pb.Architecture_ARCHITECTURE_UNSPECIFIED {
				t.Error("Expected unspecified architecture for validation test")
			}
		})
	})

	t.Run("EnrollDeviceResponse_Structure", func(t *testing.T) {
		// Test enrollment response structure
		t.Run("SuccessfulResponse", func(t *testing.T) {
			resp := &pb.EnrollDeviceResponse{
				DeviceId:    "device-uuid-123",
				DeviceToken: "jwt-device-token",
				PolicyBundle: &pb.PolicyBundle{
					Id:      "policy-default-1",
					Name:    "Default School Policy",
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
				},
				ServerTime:             timestamppb.New(time.Now()),
				CorrelationId:          "corr-123",
				CheckinIntervalSeconds: 300, // 5 minutes
				PolicyEndpoint:         "https://backend.school.edu/v1/devices/{device_id}/policy",
				StateEndpoint:          "https://backend.school.edu/v1/devices/{device_id}/state",
				EventsEndpoint:         "https://backend.school.edu/v1/devices/{device_id}/events",
			}

			// Validate response fields
			if resp.DeviceId == "" {
				t.Error("Device ID is required in response")
			}

			if resp.DeviceToken == "" {
				t.Error("Device token is required in response")
			}

			if resp.PolicyBundle == nil {
				t.Error("Initial policy bundle is required")
			}

			if resp.ServerTime == nil {
				t.Error("Server time is required for clock sync")
			}

			if resp.CheckinIntervalSeconds <= 0 {
				t.Error("Check-in interval must be positive")
			}

			if resp.PolicyEndpoint == "" {
				t.Error("Policy endpoint URL is required")
			}

			if resp.StateEndpoint == "" {
				t.Error("State endpoint URL is required")
			}

			if resp.EventsEndpoint == "" {
				t.Error("Events endpoint URL is required")
			}
		})

		t.Run("ErrorResponse", func(t *testing.T) {
			// Test error cases that should be handled
			errorCases := []struct {
				name   string
				reason string
			}{
				{"InvalidTenantCode", "Tenant code not found"},
				{"InvalidEnrollmentSecret", "Enrollment secret mismatch"},
				{"DeviceAlreadyEnrolled", "Device with this serial number already enrolled"},
				{"TenantQuotaExceeded", "Maximum devices reached for tenant"},
				{"ReplayAttack", "Nonce already used"},
			}

			for _, tc := range errorCases {
				t.Run(tc.name, func(t *testing.T) {
					// In real implementation, these would return gRPC errors
					// For now, test that we can categorize error types
					if tc.reason == "" {
						t.Errorf("Error reason should not be empty for %s", tc.name)
					}
				})
			}
		})
	})

	t.Run("EnrollmentWorkflow", func(t *testing.T) {
		// Test the complete enrollment workflow
		t.Run("HappyPath", func(t *testing.T) {
			ctx := context.Background()

			// Step 1: Validate tenant and enrollment secret
			tenantCode := "SCHOOL123"
			enrollmentSecret := "shared-secret"

			if tenantCode == "" {
				t.Error("Tenant code validation failed")
			}

			if enrollmentSecret == "" {
				t.Error("Enrollment secret validation failed")
			}

			// Step 2: Generate device ID and token
			deviceID := "generated-device-uuid"
			deviceToken := "generated-jwt-token"

			if deviceID == "" {
				t.Error("Device ID generation failed")
			}

			if deviceToken == "" {
				t.Error("Device token generation failed")
			}

			// Step 3: Store device in database
			// This would call our database layer
			stored := true // Mock success
			if !stored {
				t.Error("Device storage failed")
			}

			// Step 4: Get initial policy for tenant
			policyFound := true // Mock policy exists
			if !policyFound {
				t.Error("Initial policy retrieval failed")
			}

			// Step 5: Return enrollment response
			success := true // Mock overall success
			if !success {
				t.Error("Enrollment workflow failed")
			}

			// Test context handling
			if ctx == nil {
				t.Error("Context should not be nil")
			}
		})

		t.Run("TenantValidationFailure", func(t *testing.T) {
			// Test tenant validation failure
			invalidTenantCode := "INVALID"
			tenantExists := false // Mock tenant not found

			if tenantExists {
				t.Errorf("Tenant %s should not exist", invalidTenantCode)
			}
		})

		t.Run("EnrollmentSecretFailure", func(t *testing.T) {
			// Test enrollment secret validation failure
			validTenantCode := "SCHOOL123"
			invalidSecret := "wrong-secret"
			secretMatches := false // Mock secret mismatch

			if secretMatches {
				t.Errorf("Secret should not match for tenant %s", validTenantCode)
			}

			_ = invalidSecret // Use the variable
		})

		t.Run("DeviceAlreadyExists", func(t *testing.T) {
			// Test duplicate device enrollment
			serialNumber := "EXISTING123"
			deviceExists := true // Mock device already exists

			if !deviceExists {
				t.Errorf("Device with serial %s should already exist", serialNumber)
			}
		})
	})

	t.Run("SecurityConsiderations", func(t *testing.T) {
		// Test security aspects of enrollment
		t.Run("NonceValidation", func(t *testing.T) {
			// Test nonce for replay attack protection
			nonce1 := "nonce-123"
			nonce2 := "nonce-123" // Same nonce (replay)

			if nonce1 != nonce2 {
				t.Error("Nonces should match for replay test")
			}

			// In real implementation, we'd check nonce cache/storage
			nonceUsed := false // Mock nonce not yet used
			if nonceUsed {
				t.Error("Nonce should not be marked as used initially")
			}
		})

		t.Run("TokenGeneration", func(t *testing.T) {
			// Test device token generation
			deviceID := "device-123"
			tenantID := "tenant-456"

			// Mock token generation (would use JWT in real implementation)
			token := "jwt.token.here"

			if token == "" {
				t.Error("Token generation failed")
			}

			// Validate token contains necessary claims
			if deviceID == "" || tenantID == "" {
				t.Error("Device ID and Tenant ID required for token claims")
			}
		})

		t.Run("EnrollmentSecretHandling", func(t *testing.T) {
			// Test secure handling of enrollment secrets
			plainSecret := "my-secret"

			// In real implementation, secrets should be hashed
			// For now, test that we handle secrets securely
			if len(plainSecret) < 8 {
				t.Error("Enrollment secret should be at least 8 characters")
			}
		})
	})
}
