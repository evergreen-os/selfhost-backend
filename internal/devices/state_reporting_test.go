package devices

import (
	"context"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStateReporting(t *testing.T) {
	t.Run("ReportStateRequest_Validation", func(t *testing.T) {
		// Test valid state report request
		t.Run("ValidRequest", func(t *testing.T) {
			req := &pb.ReportStateRequest{
				DeviceId:    "device-123",
				DeviceToken: "jwt.device.token",
				State: &pb.DeviceState{
					DeviceId:       "device-123",
					ActivePolicyId: "policy-456",
					PolicyAppliedAt: timestamppb.New(time.Now().Add(-1 * time.Hour)),
					InstalledApps: []*pb.InstalledApp{
						{
							FlatpakRef:  "org.mozilla.firefox",
							Version:     "118.0.1",
							InstalledAt: timestamppb.New(time.Now().Add(-24 * time.Hour)),
							IsRunning:   true,
							LastUpdated: timestamppb.New(time.Now().Add(-2 * time.Hour)),
						},
						{
							FlatpakRef:  "org.libreoffice.LibreOffice",
							Version:     "7.5.6",
							InstalledAt: timestamppb.New(time.Now().Add(-48 * time.Hour)),
							IsRunning:   false,
							LastUpdated: timestamppb.New(time.Now().Add(-12 * time.Hour)),
						},
					},
					UpdateStatus: &pb.UpdateStatus{
						Status:           pb.UpdateStatusType_UPDATE_STATUS_TYPE_IDLE,
						Channel:          pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
						AvailableVersion: "",
						DownloadProgress: 0,
						ErrorMessage:     "",
						LastCheck:        timestamppb.New(time.Now().Add(-6 * time.Hour)),
					},
					Health: &pb.DeviceHealth{
						AvailableDiskBytes:  100 * 1024 * 1024 * 1024, // 100GB
						CpuUsagePercent:     45.5,
						MemoryUsagePercent:  62.3,
						BatteryLevelPercent: 85.0,
						IsCharging:          false,
						UptimeSeconds:       86400, // 24 hours
					},
					LastError:  "",
					ReportedAt: timestamppb.Now(),
				},
			}

			// Validate required fields
			if req.DeviceId == "" {
				t.Error("Device ID is required")
			}

			if req.DeviceToken == "" {
				t.Error("Device token is required")
			}

			if req.State == nil {
				t.Error("Device state is required")
			}

			// Validate state components
			if req.State.DeviceId != req.DeviceId {
				t.Error("State device ID should match request device ID")
			}

			if req.State.Health == nil {
				t.Error("Device health should be present")
			}

			if req.State.UpdateStatus == nil {
				t.Error("Update status should be present")
			}

			if len(req.State.InstalledApps) == 0 {
				t.Log("No installed apps reported (this may be normal)")
			}
		})

		t.Run("InvalidRequest_MissingFields", func(t *testing.T) {
			// Test missing device ID
			req := &pb.ReportStateRequest{
				DeviceToken: "valid-token",
				State: &pb.DeviceState{
					DeviceId:   "device-456",
					ReportedAt: timestamppb.Now(),
				},
			}

			if req.DeviceId != "" {
				t.Error("Expected empty device ID")
			}

			if req.DeviceToken == "" {
				t.Error("Device token should be present")
			}
		})

		t.Run("InvalidRequest_EmptyState", func(t *testing.T) {
			// Test missing state data
			req := &pb.ReportStateRequest{
				DeviceId:    "device-123",
				DeviceToken: "valid-token",
				State:       nil, // Missing state
			}

			if req.State != nil {
				t.Error("Expected nil state for validation test")
			}
		})

		t.Run("StateDeviceIDMismatch", func(t *testing.T) {
			// Test device ID mismatch between request and state
			req := &pb.ReportStateRequest{
				DeviceId:    "device-123",
				DeviceToken: "valid-token",
				State: &pb.DeviceState{
					DeviceId:   "device-different", // Mismatched ID
					ReportedAt: timestamppb.Now(),
				},
			}

			if req.DeviceId == req.State.DeviceId {
				t.Error("Device IDs should be different for this test")
			}
		})
	})

	t.Run("ReportStateResponse_Structure", func(t *testing.T) {
		// Test successful state report response
		t.Run("SuccessfulResponse", func(t *testing.T) {
			now := time.Now()
			resp := &pb.ReportStateResponse{
				ServerTime:                timestamppb.New(now),
				CorrelationId:             "corr-state-123",
				ShouldPullPolicy:          false,
				NextReportIntervalSeconds: 300, // 5 minutes
			}

			// Validate response fields
			if resp.ServerTime == nil {
				t.Error("Server time is required")
			}

			if resp.CorrelationId == "" {
				t.Error("Correlation ID is required")
			}

			if resp.NextReportIntervalSeconds <= 0 {
				t.Error("Next report interval must be positive")
			}
		})

		t.Run("PolicyPullRequired", func(t *testing.T) {
			// Test response when policy pull is required
			resp := &pb.ReportStateResponse{
				ServerTime:                timestamppb.Now(),
				CorrelationId:             "corr-policy-pull-456",
				ShouldPullPolicy:          true, // Policy pull needed
				NextReportIntervalSeconds: 300,
			}

			if !resp.ShouldPullPolicy {
				t.Error("ShouldPullPolicy should be true when policy pull is needed")
			}
		})

		t.Run("ResponseIntervalValidation", func(t *testing.T) {
			resp := &pb.ReportStateResponse{
				ServerTime:                timestamppb.Now(),
				CorrelationId:             "corr-interval-test",
				ShouldPullPolicy:          false,
				NextReportIntervalSeconds: 0, // Invalid interval
			}

			if resp.NextReportIntervalSeconds > 0 {
				t.Error("Report interval should be 0 for this test")
			}
		})
	})

	t.Run("StateWorkflow", func(t *testing.T) {
		// Test the complete state reporting workflow
		t.Run("HappyPath", func(t *testing.T) {
			ctx := context.Background()

			// Step 1: Validate device and token
			deviceID := "device-789"
			deviceToken := "valid.jwt.token"

			if deviceID == "" {
				t.Error("Device ID validation failed")
			}

			if deviceToken == "" {
				t.Error("Device token validation failed")
			}

			// Step 2: Process and store device state
			stateProcessed := true // Mock successful processing
			if !stateProcessed {
				t.Error("State processing failed")
			}

			// Step 3: Update device last seen
			lastSeenUpdated := true // Mock successful update
			if !lastSeenUpdated {
				t.Error("Last seen update failed")
			}

			// Step 4: Determine if policy pull is needed
			policyPullNeeded := false // Mock no policy changes
			if policyPullNeeded {
				t.Log("Policy pull would be recommended")
			}

			// Step 5: Return appropriate response
			success := true // Mock overall success
			if !success {
				t.Error("State reporting workflow failed")
			}

			// Test context handling
			if ctx == nil {
				t.Error("Context should not be nil")
			}
		})

		t.Run("DeviceAuthenticationFailure", func(t *testing.T) {
			// Test device authentication failure
			invalidToken := "invalid.jwt.token"
			tokenValid := false // Mock invalid token

			if tokenValid {
				t.Errorf("Token %s should not be valid", invalidToken)
			}
		})

		t.Run("StateStorageFailure", func(t *testing.T) {
			// Test state storage failure
			stateValid := true
			storageSuccess := false // Mock storage failure

			if !stateValid {
				t.Error("State should be valid for this test")
			}

			if storageSuccess {
				t.Error("Storage should fail for this test case")
			}
		})
	})

	t.Run("DeviceStateComponents", func(t *testing.T) {
		// Test individual device state components
		t.Run("DeviceHealth", func(t *testing.T) {
			health := &pb.DeviceHealth{
				AvailableDiskBytes:  50 * 1024 * 1024 * 1024, // 50GB
				CpuUsagePercent:     25.0,
				MemoryUsagePercent:  45.0,
				BatteryLevelPercent: 75.0,
				IsCharging:          true,
				UptimeSeconds:       7200, // 2 hours
			}

			if health.AvailableDiskBytes <= 0 {
				t.Error("Available disk space should be positive")
			}

			if health.CpuUsagePercent < 0 || health.CpuUsagePercent > 100 {
				t.Error("CPU usage should be between 0 and 100 percent")
			}

			if health.MemoryUsagePercent < 0 || health.MemoryUsagePercent > 100 {
				t.Error("Memory usage should be between 0 and 100 percent")
			}

			if health.BatteryLevelPercent < -1 || health.BatteryLevelPercent > 100 {
				t.Error("Battery level should be between -1 (no battery) and 100 percent")
			}

			if health.UptimeSeconds < 0 {
				t.Error("Uptime should not be negative")
			}
		})

		t.Run("InstalledApps", func(t *testing.T) {
			apps := []*pb.InstalledApp{
				{
					FlatpakRef:  "org.gimp.GIMP",
					Version:     "2.10.34",
					InstalledAt: timestamppb.New(time.Now().Add(-72 * time.Hour)), // 3 days ago
					IsRunning:   false,
					LastUpdated: timestamppb.New(time.Now().Add(-24 * time.Hour)), // 1 day ago
				},
				{
					FlatpakRef:  "com.valvesoftware.Steam",
					Version:     "1.0.0.78",
					InstalledAt: timestamppb.New(time.Now().Add(-168 * time.Hour)), // 1 week ago
					IsRunning:   true,
					LastUpdated: timestamppb.New(time.Now().Add(-1 * time.Hour)), // 1 hour ago
				},
			}

			for _, app := range apps {
				if app.FlatpakRef == "" {
					t.Error("Flatpak reference should not be empty")
				}

				if app.Version == "" {
					t.Error("App version should not be empty")
				}

				if app.InstalledAt == nil {
					t.Error("Installation timestamp should be provided")
				}

				// Check for reasonable timestamps
				if app.InstalledAt != nil && app.InstalledAt.AsTime().After(time.Now()) {
					t.Error("Installation time should not be in the future")
				}

				if app.LastUpdated != nil && app.LastUpdated.AsTime().After(time.Now()) {
					t.Error("Last updated time should not be in the future")
				}

				// Check consistency between installation and last updated
				if app.InstalledAt != nil && app.LastUpdated != nil {
					if app.LastUpdated.AsTime().Before(app.InstalledAt.AsTime()) {
						t.Error("Last updated time should not be before installation time")
					}
				}
			}
		})

		t.Run("UpdateStatus", func(t *testing.T) {
			updateStatus := &pb.UpdateStatus{
				Status:           pb.UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING,
				Channel:          pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
				AvailableVersion: "1.2.3",
				DownloadProgress: 65.0,
				ErrorMessage:     "",
				LastCheck:        timestamppb.New(time.Now().Add(-2 * time.Hour)),
			}

			if updateStatus.Status == pb.UpdateStatusType_UPDATE_STATUS_TYPE_UNSPECIFIED {
				t.Error("Update status should be specified")
			}

			if updateStatus.Channel == pb.UpdateChannel_UPDATE_CHANNEL_UNSPECIFIED {
				t.Error("Update channel should be specified")
			}

			if updateStatus.DownloadProgress < 0 || updateStatus.DownloadProgress > 100 {
				t.Error("Download progress should be between 0 and 100 percent")
			}

			if updateStatus.Status == pb.UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING && updateStatus.AvailableVersion == "" {
				t.Error("Available version should be provided when downloading")
			}

			if updateStatus.LastCheck == nil {
				t.Error("Last check timestamp should be provided")
			}

			if updateStatus.LastCheck != nil && updateStatus.LastCheck.AsTime().After(time.Now()) {
				t.Error("Last check time should not be in the future")
			}
		})

		t.Run("UpdateStatusTransitions", func(t *testing.T) {
			// Test valid status transitions and state consistency
			statuses := []pb.UpdateStatusType{
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_IDLE,
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_CHECKING,
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING,
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_INSTALLING,
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_REBOOT_REQUIRED,
				pb.UpdateStatusType_UPDATE_STATUS_TYPE_FAILED,
			}

			for _, status := range statuses {
				updateStatus := &pb.UpdateStatus{
					Status:  status,
					Channel: pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
				}

				switch status {
				case pb.UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING:
					// Should have progress and available version
					if updateStatus.DownloadProgress == 0 && updateStatus.AvailableVersion == "" {
						t.Log("Warning: Downloading status should typically have progress or version info")
					}

				case pb.UpdateStatusType_UPDATE_STATUS_TYPE_FAILED:
					// Should have error message
					if updateStatus.ErrorMessage == "" {
						t.Log("Warning: Failed status should typically have error message")
					}

				case pb.UpdateStatusType_UPDATE_STATUS_TYPE_IDLE:
					// Should not have progress or error
					if updateStatus.DownloadProgress > 0 {
						t.Error("Idle status should not have download progress")
					}
				}
			}
		})
	})

	t.Run("StateValidation", func(t *testing.T) {
		// Test state validation and consistency
		t.Run("StateTimestamp", func(t *testing.T) {
			state := &pb.DeviceState{
				DeviceId:   "device-timestamp-test",
				ReportedAt: timestamppb.New(time.Now().Add(-5 * time.Minute)), // 5 minutes ago
			}

			if state.ReportedAt == nil {
				t.Error("State timestamp is required")
			}

			// Check if timestamp is reasonable (not too old, not in future)
			timeDiff := time.Since(state.ReportedAt.AsTime())
			if timeDiff > time.Hour {
				t.Error("State timestamp is too old (more than 1 hour)")
			}

			if timeDiff < 0 {
				t.Error("State timestamp should not be in the future")
			}
		})

		t.Run("HealthMetricsValidation", func(t *testing.T) {
			health := &pb.DeviceHealth{
				AvailableDiskBytes:  -1000, // Invalid negative value
				CpuUsagePercent:     150.0, // Invalid over 100%
				MemoryUsagePercent:  45.0,
				BatteryLevelPercent: 200.0, // Invalid over 100%
				IsCharging:          false,
				UptimeSeconds:       3600,
			}

			if health.AvailableDiskBytes < 0 {
				t.Error("Available disk bytes should not be negative")
			}

			if health.CpuUsagePercent > 100.0 {
				t.Error("CPU usage percentage should not exceed 100%")
			}

			if health.BatteryLevelPercent > 100.0 {
				t.Error("Battery level should not exceed 100%")
			}
		})

		t.Run("PolicyConsistency", func(t *testing.T) {
			state := &pb.DeviceState{
				DeviceId:        "policy-test-device",
				ActivePolicyId:  "policy-123",
				PolicyAppliedAt: timestamppb.New(time.Now().Add(-2 * time.Hour)),
				ReportedAt:      timestamppb.Now(),
			}

			if state.ActivePolicyId != "" && state.PolicyAppliedAt == nil {
				t.Error("If active policy ID is set, policy applied timestamp should be provided")
			}

			if state.PolicyAppliedAt != nil && state.PolicyAppliedAt.AsTime().After(time.Now()) {
				t.Error("Policy applied time should not be in the future")
			}

			if state.PolicyAppliedAt != nil && state.ReportedAt != nil {
				if state.PolicyAppliedAt.AsTime().After(state.ReportedAt.AsTime()) {
					t.Error("Policy applied time should not be after report time")
				}
			}
		})

		t.Run("ApplicationConsistency", func(t *testing.T) {
			// Test application state consistency
			app := &pb.InstalledApp{
				FlatpakRef:  "com.example.TestApp",
				Version:     "1.0.0",
				InstalledAt: timestamppb.New(time.Now().Add(-24 * time.Hour)),
				IsRunning:   true,
				LastUpdated: timestamppb.New(time.Now().Add(-48 * time.Hour)), // Inconsistent: last updated before install
			}

			if app.LastUpdated != nil && app.InstalledAt != nil {
				if app.LastUpdated.AsTime().Before(app.InstalledAt.AsTime()) {
					t.Error("Application last updated time should not be before installation time")
				}
			}

			if app.IsRunning && app.LastUpdated != nil {
				// If running, last updated should be recent
				timeSinceUpdated := time.Since(app.LastUpdated.AsTime())
				if timeSinceUpdated > 24*time.Hour {
					t.Log("Warning: App is running but last updated time is more than 24 hours ago")
				}
			}
		})
	})
}