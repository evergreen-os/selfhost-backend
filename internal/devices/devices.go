package devices

import (
	"context"
	"fmt"
	"time"

	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PullPolicy handles policy pull requests
func (s *DeviceService) PullPolicy(ctx context.Context, req *pb.PullPolicyRequest) (*pb.PullPolicyResponse, error) {
	// Validate request
	if err := s.validatePolicyRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid policy request: %v", err)
	}

	// Step 1: Validate device and token
	device, err := s.validateDeviceToken(ctx, req.DeviceId, req.DeviceToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "device authentication failed: %v", err)
	}

	// Step 2: Get latest policy for device's tenant
	latestPolicy, err := s.getLatestPolicyForDevice(ctx, device.TenantID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get latest policy: %v", err)
	}

	// Step 3: Check if policy update is needed
	updateNeeded := s.isPolicyUpdateNeeded(req.CurrentPolicyVersion, latestPolicy.Version)

	// Step 4: Prepare response
	response := &pb.PullPolicyResponse{
		PolicyUpdated: updateNeeded,
		ServerTime:    timestamppb.Now(),
		NextCheckin:   timestamppb.Now(), // TODO: Calculate next check-in time
		CorrelationId: generateCorrelationID(),
	}

	if updateNeeded {
		response.PolicyBundle = latestPolicy
	}

	// Step 5: Update device last seen
	if err := s.updateDeviceLastSeen(ctx, req.DeviceId); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to update device last seen: %v\n", err)
	}

	return response, nil
}

// ReportState handles device state reporting
func (s *DeviceService) ReportState(ctx context.Context, req *pb.ReportStateRequest) (*pb.ReportStateResponse, error) {
	// Validate request
	if err := s.validateStateRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid state request: %v", err)
	}

	// Step 1: Validate device and token
	_, err := s.validateDeviceToken(ctx, req.DeviceId, req.DeviceToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "device authentication failed: %v", err)
	}

	// Step 2: Store device state
	if err := s.storeDeviceState(ctx, req); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store device state: %v", err)
	}

	// Step 3: Update device last seen
	if err := s.updateDeviceLastSeen(ctx, req.DeviceId); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to update device last seen: %v\n", err)
	}

	// Step 4: Prepare response
	response := &pb.ReportStateResponse{
		ServerTime:                  timestamppb.Now(),
		CorrelationId:               generateCorrelationID(),
		ShouldPullPolicy:            false, // TODO: Determine if policy pull is needed
		NextReportIntervalSeconds:   300,   // 5 minutes
	}

	return response, nil
}

// validatePolicyRequest validates the policy pull request
func (s *DeviceService) validatePolicyRequest(req *pb.PullPolicyRequest) error {
	if req.DeviceId == "" {
		return fmt.Errorf("device ID is required")
	}

	if req.DeviceToken == "" {
		return fmt.Errorf("device token is required")
	}

	if req.RequestTime == nil {
		return fmt.Errorf("request time is required")
	}

	return nil
}

// validateStateRequest validates the state report request
func (s *DeviceService) validateStateRequest(req *pb.ReportStateRequest) error {
	if req.DeviceId == "" {
		return fmt.Errorf("device ID is required")
	}

	if req.DeviceToken == "" {
		return fmt.Errorf("device token is required")
	}

	if req.State == nil {
		return fmt.Errorf("device state is required")
	}

	return nil
}

// validateDeviceToken validates device authentication
func (s *DeviceService) validateDeviceToken(ctx context.Context, deviceID, token string) (*generated.Device, error) {
	// In production, this should validate the JWT token
	// For now, we'll do basic device lookup
	device, err := s.db.Queries().GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device not found: %w", err)
	}

	// TODO: Validate JWT token signature and claims
	_ = token

	return &device, nil
}

// isPolicyUpdateNeeded determines if a policy update is needed
func (s *DeviceService) isPolicyUpdateNeeded(currentVersion, latestVersion *timestamppb.Timestamp) bool {
	if currentVersion == nil {
		return true // First time, always need policy
	}

	if latestVersion == nil {
		return false // No policy available
	}

	return latestVersion.AsTime().After(currentVersion.AsTime())
}

// getLatestPolicyForDevice gets the latest policy for a device's tenant
func (s *DeviceService) getLatestPolicyForDevice(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
	// Try to get the latest signed policy from the policy service
	policyBundle, err := s.policyService.GetLatestPolicyByTenant(ctx, tenantID)
	if err != nil {
		// Return a default signed policy if none exists
		return s.policyService.GetDefaultPolicy(), nil
	}

	return policyBundle, nil
}

// updateDeviceLastSeen updates the device's last seen timestamp
func (s *DeviceService) updateDeviceLastSeen(ctx context.Context, deviceID string) error {
	// Update device last_seen_at timestamp in database
	_, err := s.db.Queries().UpdateDeviceLastSeen(ctx, generated.UpdateDeviceLastSeenParams{
		DeviceID:   deviceID,
		LastSeenAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
	return err
}

// storeDeviceState stores the reported device state
func (s *DeviceService) storeDeviceState(ctx context.Context, req *pb.ReportStateRequest) error {
	// Convert protobuf state to database format and store
	// For now, this is a placeholder
	_ = ctx
	_ = req
	return nil
}