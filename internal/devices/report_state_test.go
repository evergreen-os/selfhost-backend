package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeStateProcessor struct {
	processCalledFor string
	processState     *pb.DeviceState
	analysis         *StateAnalysis
	processErr       error

	shouldPull   bool
	pullReason   string
	determineErr error

	nextInterval int32
}

func (f *fakeStateProcessor) ProcessDeviceState(ctx context.Context, deviceID string, state *pb.DeviceState) (*StateAnalysis, error) {
	f.processCalledFor = deviceID
	f.processState = state
	if f.processErr != nil {
		return nil, f.processErr
	}
	if f.analysis != nil {
		return f.analysis, nil
	}
	return &StateAnalysis{}, nil
}

func (f *fakeStateProcessor) DeterminePolicyPullRequired(ctx context.Context, deviceID string, state *pb.DeviceState) (bool, string, error) {
	if f.determineErr != nil {
		return false, "", f.determineErr
	}
	return f.shouldPull, f.pullReason, nil
}

func (f *fakeStateProcessor) CalculateNextReportInterval(analysis *StateAnalysis) int32 {
	if f.nextInterval == 0 {
		return 300
	}
	return f.nextInterval
}

func TestReportStateReturnsProcessorResults(t *testing.T) {
	t.Parallel()

	deviceID := "device-123"
	tenantID := pgtype.UUID{}
	_ = tenantID.Scan("6b5b4818-0e7c-4fef-a4eb-9c51394ceaaa")

	tokenManager := newDeviceTokenManager(t)
	tenantUUID, err := uuid.FromBytes(tenantID.Bytes[:])
	if err != nil {
		t.Fatalf("failed to parse tenant id: %v", err)
	}
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken(deviceID, tenantUUID.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, id string) (generated.Device, error) {
			if id != deviceID {
				t.Fatalf("unexpected device lookup: %s", id)
			}
			return generated.Device{TenantID: tenantID, DeviceTokenHash: hashedToken}, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, params generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			if params.DeviceID != deviceID {
				t.Fatalf("unexpected device for last seen: %s", params.DeviceID)
			}
			if !params.LastSeenAt.Valid {
				t.Fatal("expected valid last seen timestamp")
			}
			return generated.Device{}, nil
		},
	}

	processor := &fakeStateProcessor{
		analysis: &StateAnalysis{
			Alerts: []string{"Critical: disk"},
		},
		shouldPull:   true,
		pullReason:   "New policy",
		nextInterval: 600,
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, &fakeEventsRecorder{}, nil)
	service.stateProcessorFactory = func(DeviceStore) StateProcessorInterface {
		return processor
	}

	req := &pb.ReportStateRequest{
		DeviceId:    deviceID,
		DeviceToken: rawToken,
		State: &pb.DeviceState{
			DeviceId:       deviceID,
			ActivePolicyId: "policy-1",
			ReportedAt:     timestamppb.New(time.Now()),
		},
	}

	resp, err := service.ReportState(context.Background(), req)
	if err != nil {
		t.Fatalf("ReportState returned error: %v", err)
	}

	if processor.processCalledFor != deviceID {
		t.Fatalf("expected processor to be called for %s, got %s", deviceID, processor.processCalledFor)
	}

	if !resp.ShouldPullPolicy {
		t.Fatal("expected response to request policy pull")
	}

	if resp.NextReportIntervalSeconds != 600 {
		t.Fatalf("expected next interval 600, got %d", resp.NextReportIntervalSeconds)
	}

	if resp.ServerTime == nil {
		t.Fatal("expected server time to be set")
	}
}

func TestReportStateValidatesRequest(t *testing.T) {
	t.Parallel()

	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.ReportState(context.Background(), &pb.ReportStateRequest{})
	if err == nil {
		t.Fatal("expected validation error")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestReportStateFailsForUnknownDevice(t *testing.T) {
	t.Parallel()

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			return generated.Device{}, errors.New("missing")
		},
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	req := &pb.ReportStateRequest{
		DeviceId:    "unknown",
		DeviceToken: "token",
		State:       &pb.DeviceState{DeviceId: "unknown", ReportedAt: timestamppb.Now()},
	}

	_, err := service.ReportState(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown device")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %s", st.Code())
	}
}

func TestReportStatePropagatesProcessorError(t *testing.T) {
	t.Parallel()

	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(uuid.New().String())
	tokenManager := newDeviceTokenManager(t)
	tenantUUIDValue, err := uuid.FromBytes(tenantUUID.Bytes[:])
	if err != nil {
		t.Fatalf("failed to parse tenant id: %v", err)
	}
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken("device-1", tenantUUIDValue.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, id string) (generated.Device, error) {
			deviceUUID := pgtype.UUID{}
			_ = deviceUUID.Scan(uuid.New().String())
			return generated.Device{TenantID: tenantUUID, DeviceTokenHash: hashedToken, ID: deviceUUID}, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, params generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			return generated.Device{}, nil
		},
	}

	processor := &fakeStateProcessor{processErr: errors.New("boom")}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, &fakeEventsRecorder{}, nil)
	service.stateProcessorFactory = func(DeviceStore) StateProcessorInterface { return processor }

	req := &pb.ReportStateRequest{
		DeviceId:    "device-1",
		DeviceToken: rawToken,
		State:       &pb.DeviceState{DeviceId: "device-1", ReportedAt: timestamppb.Now()},
	}

	_, procErr := service.ReportState(context.Background(), req)
	if procErr == nil {
		t.Fatal("expected error from processor")
	}

	st, _ := status.FromError(procErr)
	if st.Code() != codes.Internal {
		t.Fatalf("expected Internal error, got %s", st.Code())
	}
}

func TestReportStateHandlesPolicyDeterminationErrorGracefully(t *testing.T) {
	t.Parallel()

	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(uuid.New().String())
	tokenManager := newDeviceTokenManager(t)
	tenantUUIDValue, err := uuid.FromBytes(tenantUUID.Bytes[:])
	if err != nil {
		t.Fatalf("failed to parse tenant id: %v", err)
	}
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken("device-1", tenantUUIDValue.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, id string) (generated.Device, error) {
			deviceUUID := pgtype.UUID{}
			_ = deviceUUID.Scan(uuid.New().String())
			return generated.Device{TenantID: tenantUUID, DeviceTokenHash: hashedToken, ID: deviceUUID}, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, params generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			return generated.Device{}, nil
		},
	}

	processor := &fakeStateProcessor{determineErr: errors.New("policy lookup failed")}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, &fakeEventsRecorder{}, nil)
	service.stateProcessorFactory = func(DeviceStore) StateProcessorInterface { return processor }

	req := &pb.ReportStateRequest{
		DeviceId:    "device-1",
		DeviceToken: rawToken,
		State:       &pb.DeviceState{DeviceId: "device-1", ReportedAt: timestamppb.Now()},
	}

	resp, procErr := service.ReportState(context.Background(), req)
	if procErr != nil {
		t.Fatalf("did not expect error when policy determination fails softly: %v", procErr)
	}

	if resp.ShouldPullPolicy {
		t.Fatal("expected ShouldPullPolicy to be false when determination fails")
	}
}
