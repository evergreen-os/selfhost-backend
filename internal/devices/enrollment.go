package devices

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/attestation"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"github.com/evergreenos/selfhost-backend/internal/config"
	"github.com/evergreenos/selfhost-backend/internal/db"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/evergreenos/selfhost-backend/internal/events"
	"github.com/evergreenos/selfhost-backend/internal/policies"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DeviceStore defines the subset of persistence operations required by the device service.
type DeviceStore interface {
	GetTenantByCode(ctx context.Context, tenantCode string) (generated.Tenant, error)
	CreateDevice(ctx context.Context, arg generated.CreateDeviceParams) (generated.Device, error)
	GetDeviceByID(ctx context.Context, deviceID string) (generated.Device, error)
	UpdateDeviceLastSeen(ctx context.Context, arg generated.UpdateDeviceLastSeenParams) (generated.Device, error)
	UpsertDeviceState(ctx context.Context, arg generated.UpsertDeviceStateParams) (generated.DeviceState, error)
	GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (generated.Policy, error)
	GetDeviceBySerialNumber(ctx context.Context, hardwareSerialNumber *string) (generated.Device, error)
}

// PolicyProvider exposes policy retrieval required by the device service.
type PolicyProvider interface {
	GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error)
	GetDefaultPolicy() *pb.PolicyBundle
}

// DeviceService implements the gRPC DeviceService
type DeviceService struct {
	pb.UnimplementedDeviceServiceServer
	store                 DeviceStore
	policyService         PolicyProvider
	tokenManager          *auth.Manager
	events                eventsRecorder
	stateProcessorFactory func(DeviceStore) StateProcessorInterface
	attestor              QuoteVerifier
}

type eventsRecorder interface {
	IngestBatch(ctx context.Context, device generated.Device, events []*pb.DeviceEvent) (int, error)
}

// NewDeviceService creates a new device service
func NewDeviceService(database *db.DB, tokenManager *auth.Manager) (*DeviceService, error) {
	if tokenManager == nil {
		return nil, fmt.Errorf("token manager is required")
	}
        policyService, err := policies.NewPolicyService(database.Queries(), config.PolicyConfig{})
	if err != nil {
		return nil, fmt.Errorf("failed to create policy service: %w", err)
	}

	eventsService, err := events.NewService(database.Queries(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create events service: %w", err)
	}

	verifier, err := attestation.NewVerifier(5 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation verifier: %w", err)
	}

	return NewDeviceServiceWithDependencies(database.Queries(), policyService, tokenManager, eventsService, verifier), nil
}

// NewDeviceServiceWithDependencies allows tests to provide mock implementations.
func NewDeviceServiceWithDependencies(store DeviceStore, policyService PolicyProvider, tokenManager *auth.Manager, events eventsRecorder, attestor QuoteVerifier) *DeviceService {
	return &DeviceService{
		store:         store,
		policyService: policyService,
		tokenManager:  tokenManager,
		events:        events,
		stateProcessorFactory: func(ds DeviceStore) StateProcessorInterface {
			return NewStateProcessor(ds, events)
		},
		attestor: attestor,
	}
}

// EnrollDevice handles device enrollment requests
func (s *DeviceService) EnrollDevice(ctx context.Context, req *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	// Validate request
	if err := s.validateEnrollmentRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid enrollment request: %v", err)
	}

	// Step 1: Validate tenant and enrollment secret
	tenant, err := s.validateTenant(ctx, req.EnrollmentToken, req.EnrollmentSecret)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "tenant validation failed: %v", err)
	}

	// Step 2: Check for duplicate device
	if err := s.checkDuplicateDevice(ctx, req.Hardware.SerialNumber); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "device already enrolled: %v", err)
	}

	// Step 3: Generate device ID and token
	deviceID := uuid.New().String()
	tenantUUID, err := uuid.FromBytes(tenant.ID.Bytes[:])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to format tenant id: %v", err)
	}

	deviceToken, hashedToken, err := s.tokenManager.IssueDeviceToken(deviceID, tenantUUID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate device token: %v", err)
	}

	// Step 4: Store device in database
	_, err = s.createDevice(ctx, deviceID, tenant.ID, hashedToken, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create device: %v", err)
	}

	// Step 5: Get initial policy for tenant
	policyBundle, err := s.getInitialPolicy(ctx, tenant.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get initial policy: %v", err)
	}

	// Step 6: Return enrollment response
	response := &pb.EnrollDeviceResponse{
		DeviceId:               deviceID,
		DeviceToken:            deviceToken,
		PolicyBundle:           policyBundle,
		ServerTime:             timestamppb.Now(),
		CorrelationId:          generateCorrelationID(),
		CheckinIntervalSeconds: 300, // 5 minutes
		PolicyEndpoint:         fmt.Sprintf("/v1/devices/%s/policy", deviceID),
		StateEndpoint:          fmt.Sprintf("/v1/devices/%s/state", deviceID),
		EventsEndpoint:         fmt.Sprintf("/v1/devices/%s/events", deviceID),
	}

	return response, nil
}

// validateEnrollmentRequest validates the enrollment request
func (s *DeviceService) validateEnrollmentRequest(req *pb.EnrollDeviceRequest) error {
	if req.EnrollmentToken == "" {
		return fmt.Errorf("enrollment token is required")
	}

	if req.Hardware == nil {
		return fmt.Errorf("hardware information is required")
	}

	if req.Hardware.Model == "" {
		return fmt.Errorf("hardware model is required")
	}

	if req.Hardware.SerialNumber == "" {
		return fmt.Errorf("hardware serial number is required")
	}

	if req.OsInfo == nil {
		return fmt.Errorf("OS information is required")
	}

	if req.Network == nil {
		return fmt.Errorf("network information is required")
	}

	if req.AgentVersion == nil {
		return fmt.Errorf("agent version is required")
	}

	if req.Nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}

	return nil
}

// validateTenant validates the tenant code and enrollment secret
func (s *DeviceService) validateTenant(ctx context.Context, tenantCode, enrollmentSecret string) (*generated.Tenant, error) {
	tenant, err := s.store.GetTenantByCode(ctx, tenantCode)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.EnrollmentSecretHash == "" {
		return nil, fmt.Errorf("enrollment secret not configured")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(tenant.EnrollmentSecretHash), []byte(enrollmentSecret)); err != nil {
		return nil, fmt.Errorf("invalid enrollment secret")
	}

	return &tenant, nil
}

// checkDuplicateDevice checks if a device with the same serial number is already enrolled
func (s *DeviceService) checkDuplicateDevice(ctx context.Context, serialNumber string) error {
	if strings.TrimSpace(serialNumber) == "" {
		return nil
	}
	device, err := s.store.GetDeviceBySerialNumber(ctx, &serialNumber)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("check duplicates: %w", err)
	}
	if device.DeviceID != "" {
		return fmt.Errorf("device with serial number already exists")
	}
	return nil
}

// createDevice stores the device in the database
func (s *DeviceService) createDevice(ctx context.Context, deviceID string, tenantID pgtype.UUID, hashedToken string, req *pb.EnrollDeviceRequest) (*generated.Device, error) {
	model := req.Hardware.Model
	manufacturer := req.Hardware.Manufacturer
	serialNumber := req.Hardware.SerialNumber
	architecture := req.Hardware.Architecture.String()
	osName := req.OsInfo.Name
	osVersion := req.OsInfo.Version
	hostname := req.Network.Hostname
	agentVersion := req.AgentVersion.Version

	params := generated.CreateDeviceParams{
		DeviceID:                  deviceID,
		TenantID:                  tenantID,
		DeviceTokenHash:           hashedToken,
		Status:                    "enrolled",
		HardwareModel:             &model,
		HardwareManufacturer:      &manufacturer,
		HardwareSerialNumber:      &serialNumber,
		HardwareArchitecture:      &architecture,
		HardwareTotalMemoryBytes:  &req.Hardware.TotalMemoryBytes,
		HardwareTotalStorageBytes: &req.Hardware.TotalStorageBytes,
		// TODO: Add TPM fields when protobuf field names are resolved
		OsName:            &osName,
		OsVersion:         &osVersion,
		OsKernelVersion:   &req.OsInfo.KernelVersion,
		OsBuildID:         &req.OsInfo.BuildId,
		NetworkHostname:   &hostname,
		NetworkPrimaryMac: &req.Network.PrimaryMacAddress,
		AgentVersion:      &agentVersion,
		AgentCommit:       &req.AgentVersion.Commit,
		EnrolledAt:        pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}

	device, err := s.store.CreateDevice(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create device in database: %w", err)
	}

	return &device, nil
}

// getInitialPolicy retrieves the initial policy for a tenant
func (s *DeviceService) getInitialPolicy(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
	// Try to get the latest signed policy from the policy service
	policyBundle, err := s.policyService.GetLatestPolicyByTenant(ctx, tenantID)
	if err != nil {
		// Return a default signed policy if none exists
		return s.policyService.GetDefaultPolicy(), nil
	}

	return policyBundle, nil
}

// getDefaultPolicy returns a default policy bundle
func (s *DeviceService) getDefaultPolicy() *pb.PolicyBundle {
	return &pb.PolicyBundle{
		Id:      "default-policy",
		Name:    "Default Policy",
		Version: timestamppb.Now(),
		Apps: &pb.AppPolicy{
			AutoInstallRequired:   true,
			AutoRemoveForbidden:   true,
			InstallTimeoutSeconds: 300,
		},
		Updates: &pb.UpdatePolicy{
			Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
			AutoInstall: false,
			AutoReboot:  false,
		},
	}
}

// generateCorrelationID generates a correlation ID for request tracing
func generateCorrelationID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("corr-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("corr-%x", bytes)
}
