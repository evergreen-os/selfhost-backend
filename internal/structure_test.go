package internal

import (
	"testing"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
)

func TestProjectStructure(t *testing.T) {
	t.Run("GeneratedProtobufCode", func(t *testing.T) {
		// Test that all main protobuf messages can be created
		testCases := []struct {
			name    string
			creator func() interface{}
		}{
			{"EnrollDeviceRequest", func() interface{} { return &pb.EnrollDeviceRequest{} }},
			{"EnrollDeviceResponse", func() interface{} { return &pb.EnrollDeviceResponse{} }},
			{"PullPolicyRequest", func() interface{} { return &pb.PullPolicyRequest{} }},
			{"PullPolicyResponse", func() interface{} { return &pb.PullPolicyResponse{} }},
			{"ReportStateRequest", func() interface{} { return &pb.ReportStateRequest{} }},
			{"ReportStateResponse", func() interface{} { return &pb.ReportStateResponse{} }},
			{"ReportEventsRequest", func() interface{} { return &pb.ReportEventsRequest{} }},
			{"ReportEventsResponse", func() interface{} { return &pb.ReportEventsResponse{} }},
			{"PolicyBundle", func() interface{} { return &pb.PolicyBundle{} }},
			{"DeviceEvent", func() interface{} { return &pb.DeviceEvent{} }},
			{"Device", func() interface{} { return &pb.Device{} }},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				obj := tc.creator()
				if obj == nil {
					t.Errorf("Failed to create %s", tc.name)
				}
			})
		}
	})

	t.Run("EnrollmentWorkflow", func(t *testing.T) {
		// Test a basic enrollment workflow with the generated types
		req := &pb.EnrollDeviceRequest{
			EnrollmentToken: "test-token",
			Hardware: &pb.HardwareInfo{
				Model:        "Test Device",
				Manufacturer: "Test Corp",
				SerialNumber: "TEST123",
				Architecture: pb.Architecture_ARCHITECTURE_AMD64,
			},
			OsInfo: &pb.OSInfo{
				Name:    "EvergreenOS",
				Version: "1.0.0",
			},
			AgentVersion: &pb.Version{
				Version: "1.0.0",
				Commit:  "abc123",
			},
		}

		if req.EnrollmentToken != "test-token" {
			t.Errorf("Expected enrollment token 'test-token', got %s", req.EnrollmentToken)
		}

		if req.Hardware.Model != "Test Device" {
			t.Errorf("Expected hardware model 'Test Device', got %s", req.Hardware.Model)
		}

		// Test response creation
		resp := &pb.EnrollDeviceResponse{
			DeviceId:    "device-123",
			DeviceToken: "token-456",
			PolicyBundle: &pb.PolicyBundle{
				Id:   "policy-1",
				Name: "Default Policy",
			},
		}

		if resp.DeviceId != "device-123" {
			t.Errorf("Expected device ID 'device-123', got %s", resp.DeviceId)
		}
	})

	t.Run("PolicyManagement", func(t *testing.T) {
		// Test policy bundle creation and structure
		policy := &pb.PolicyBundle{
			Id:   "policy-test",
			Name: "Test Policy",
			Apps: &pb.AppPolicy{
				AutoInstallRequired:  true,
				AutoRemoveForbidden:  true,
				InstallTimeoutSeconds: 300,
			},
			Updates: &pb.UpdatePolicy{
				Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
				AutoInstall: true,
				AutoReboot:  false,
			},
			Security: &pb.SecurityPolicy{
				SelinuxEnforcing:           true,
				DisableSsh:                 false,
				RequireScreenLock:          true,
				ScreenLockTimeoutSeconds:   300,
			},
		}

		if policy.Apps.AutoInstallRequired != true {
			t.Error("Expected auto install required to be true")
		}

		if policy.Updates.Channel != pb.UpdateChannel_UPDATE_CHANNEL_STABLE {
			t.Error("Expected update channel to be stable")
		}
	})

	t.Run("EventSystem", func(t *testing.T) {
		// Test event creation and reporting
		event := &pb.DeviceEvent{
			EventId:  "event-123",
			DeviceId: "device-456",
			Type:     pb.EventType_EVENT_TYPE_APP_INSTALL,
			Level:    pb.EventLevel_EVENT_LEVEL_INFO,
			Message:  "Application installed successfully",
			Metadata: map[string]string{
				"app_id":  "com.example.app",
				"version": "1.2.3",
			},
		}

		if event.Type != pb.EventType_EVENT_TYPE_APP_INSTALL {
			t.Error("Expected event type to be APP_INSTALL")
		}

		if event.Level != pb.EventLevel_EVENT_LEVEL_INFO {
			t.Error("Expected event level to be INFO")
		}

		// Test batch reporting
		batchReq := &pb.ReportEventsRequest{
			DeviceId:    "device-456",
			DeviceToken: "token-789",
			Events:      []*pb.DeviceEvent{event},
		}

		if len(batchReq.Events) != 1 {
			t.Errorf("Expected 1 event in batch, got %d", len(batchReq.Events))
		}
	})
}