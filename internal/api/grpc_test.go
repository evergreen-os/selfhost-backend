package api

import (
	"testing"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
)

func TestGeneratedCodeImports(t *testing.T) {
	// Test that generated protobuf code compiles and can be imported
	req := &pb.EnrollDeviceRequest{
		EnrollmentToken: "test-token",
	}

	if req.EnrollmentToken != "test-token" {
		t.Errorf("Expected enrollment token to be 'test-token', got %s", req.EnrollmentToken)
	}

	// Test other message types
	_ = &pb.PullPolicyRequest{}
	_ = &pb.ReportStateRequest{}
	_ = &pb.ReportEventsRequest{}
	_ = &pb.PolicyBundle{}
	_ = &pb.DeviceEvent{}
}