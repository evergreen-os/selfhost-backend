package devices

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/attestation"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultPolicyCheckinInterval = 5 * time.Minute
)

type QuoteVerifier interface {
	Verify(attestation.Quote) error
}

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
	now := time.Now()
	response := &pb.PullPolicyResponse{
		PolicyUpdated: updateNeeded,
		ServerTime:    timestamppb.New(now),
		NextCheckin:   timestamppb.New(now.Add(defaultPolicyCheckinInterval)),
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

	// Step 2: Process device state with comprehensive analysis
	processor := s.stateProcessorFactory(s.store)
	if processor == nil {
		processor = NewStateProcessor(s.store, s.events)
	}
	analysis, err := processor.ProcessDeviceState(ctx, req.DeviceId, req.State)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to process device state: %v", err)
	}

	// Step 3: Update device last seen
	if err := s.updateDeviceLastSeen(ctx, req.DeviceId); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to update device last seen: %v\n", err)
	}

	// Step 4: Determine if policy pull is required
	shouldPullPolicy, policyReason, err := processor.DeterminePolicyPullRequired(ctx, req.DeviceId, req.State)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to determine policy pull requirement: %v\n", err)
		shouldPullPolicy = false
	}

	// Step 5: Calculate next report interval based on device state
	nextInterval := processor.CalculateNextReportInterval(analysis)

	// Step 6: Prepare response
	response := &pb.ReportStateResponse{
		ServerTime:                timestamppb.Now(),
		CorrelationId:             generateCorrelationID(),
		ShouldPullPolicy:          shouldPullPolicy,
		NextReportIntervalSeconds: nextInterval,
	}

	// Log policy pull reason if applicable
	if shouldPullPolicy && policyReason != "" {
		fmt.Printf("Device %s requires policy pull: %s\n", req.DeviceId, policyReason)
	}

	// Log critical alerts
	for _, alert := range analysis.Alerts {
		if containsString(alert, "Critical:") {
			fmt.Printf("CRITICAL ALERT for device %s: %s\n", req.DeviceId, alert)
		}
	}

	return response, nil
}

// ReportEvents handles ingestion of batched device events.
func (s *DeviceService) ReportEvents(ctx context.Context, req *pb.ReportEventsRequest) (*pb.ReportEventsResponse, error) {
	if err := s.validateEventsRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid events request: %v", err)
	}

	device, err := s.validateDeviceToken(ctx, req.DeviceId, req.DeviceToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "device authentication failed: %v", err)
	}

	for _, event := range req.Events {
		if err := s.validateEventPayload(event); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "event validation failed: %v", err)
		}
	}

	acceptedCount := int32(0)
	if s.events != nil {
		accepted, err := s.events.IngestBatch(ctx, *device, req.Events)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to store events: %v", err)
		}
		acceptedCount = int32(accepted)
	} else {
		acceptedCount = int32(len(req.Events))
	}

	if err := s.updateDeviceLastSeen(ctx, req.DeviceId); err != nil {
		fmt.Printf("Failed to update device last seen during event upload: %v\n", err)
	}

	return &pb.ReportEventsResponse{
		AcceptedEvents: acceptedCount,
		RejectedEvents: 0,
		ServerTime:     timestamppb.Now(),
		CorrelationId:  generateCorrelationID(),
	}, nil
}

// AttestBoot verifies a device supplied boot attestation quote.
func (s *DeviceService) AttestBoot(ctx context.Context, req *pb.AttestBootRequest) (*pb.AttestBootResponse, error) {
	if s.attestor == nil {
		return nil, status.Error(codes.Unimplemented, "attestation disabled")
	}
	if err := s.validateAttestationRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid attestation request: %v", err)
	}
	if _, err := s.validateDeviceToken(ctx, req.DeviceId, req.DeviceToken); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "device authentication failed: %v", err)
	}

	quote := attestation.Quote{
		Nonce:         req.Nonce,
		ExpectedNonce: req.ExpectedNonce,
		Quote:         req.Quote,
		Signature:     req.Signature,
		ProducedAt:    req.ProducedAt.AsTime(),
	}
	if err := s.attestor.Verify(quote); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "attestation failed: %v", err)
	}

	if err := s.updateDeviceLastSeen(ctx, req.DeviceId); err != nil {
		fmt.Printf("Failed to update device last seen during attestation: %v\n", err)
	}

	return &pb.AttestBootResponse{
		Verified:      true,
		ServerTime:    timestamppb.Now(),
		CorrelationId: generateCorrelationID(),
	}, nil
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
	device, err := s.store.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device not found: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("device token is required")
	}

	if !device.TenantID.Valid {
		return nil, fmt.Errorf("device tenant is invalid")
	}

	tenantUUID, err := uuid.FromBytes(device.TenantID.Bytes[:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant id: %w", err)
	}

	if device.DeviceTokenHash == "" {
		return nil, fmt.Errorf("device token hash missing")
	}

	if _, err := s.tokenManager.VerifyDeviceToken(token, deviceID, tenantUUID.String(), device.DeviceTokenHash); err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

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
	_, err := s.store.UpdateDeviceLastSeen(ctx, generated.UpdateDeviceLastSeenParams{
		DeviceID:   deviceID,
		LastSeenAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
	return err
}

// validateEventsRequest ensures the batched event payload has required information.
func (s *DeviceService) validateEventsRequest(req *pb.ReportEventsRequest) error {
	if req.DeviceId == "" {
		return fmt.Errorf("device ID is required")
	}
	if req.DeviceToken == "" {
		return fmt.Errorf("device token is required")
	}
	if len(req.Events) == 0 {
		return fmt.Errorf("at least one event is required")
	}
	if req.BatchTime != nil {
		if req.BatchTime.AsTime().After(time.Now().Add(5 * time.Minute)) {
			return fmt.Errorf("batch time is too far in the future")
		}
	}
	return nil
}

func (s *DeviceService) validateAttestationRequest(req *pb.AttestBootRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.DeviceId == "" {
		return fmt.Errorf("device ID is required")
	}
	if req.DeviceToken == "" {
		return fmt.Errorf("device token is required")
	}
	if req.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if req.ExpectedNonce == "" {
		return fmt.Errorf("expected nonce is required")
	}
	if len(req.Quote) == 0 {
		return fmt.Errorf("quote payload is required")
	}
	if len(req.Signature) == 0 {
		return fmt.Errorf("signature is required")
	}
	if req.ProducedAt == nil {
		return fmt.Errorf("produced_at timestamp is required")
	}
	if req.ProducedAt.AsTime().IsZero() {
		return fmt.Errorf("produced_at timestamp is invalid")
	}
	return nil
}

func (s *DeviceService) validateEventPayload(event *pb.DeviceEvent) error {
	if event == nil {
		return fmt.Errorf("event payload missing")
	}
	if event.EventId == "" {
		return fmt.Errorf("event id is required")
	}
	if event.Timestamp == nil {
		return fmt.Errorf("event timestamp is required")
	}
	if event.Type == pb.EventType_EVENT_TYPE_UNSPECIFIED {
		return fmt.Errorf("event type must be specified")
	}
	if event.Level == pb.EventLevel_EVENT_LEVEL_UNSPECIFIED {
		return fmt.Errorf("event level must be specified")
	}
	if strings.TrimSpace(event.Message) == "" {
		return fmt.Errorf("event message is required")
	}
	return nil
}

// storeDeviceState stores the reported device state
func (s *DeviceService) storeDeviceState(ctx context.Context, req *pb.ReportStateRequest) error {
	_ = ctx
	_ = req
	return nil
}
