package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeDeviceStore struct {
	getTenantByCodeFn       func(ctx context.Context, tenantCode string) (generated.Tenant, error)
	createDeviceFn          func(ctx context.Context, arg generated.CreateDeviceParams) (generated.Device, error)
	getDeviceByIDFn         func(ctx context.Context, deviceID string) (generated.Device, error)
	updateDeviceLastSeenFn  func(ctx context.Context, arg generated.UpdateDeviceLastSeenParams) (generated.Device, error)
	upsertDeviceStateFn     func(ctx context.Context, arg generated.UpsertDeviceStateParams) (generated.DeviceState, error)
	getLatestPolicyTenantFn func(ctx context.Context, tenantID pgtype.UUID) (generated.Policy, error)
	getDeviceBySerialFn     func(ctx context.Context, serial *string) (generated.Device, error)
}

type fakeEventsRecorder struct {
	err   error
	calls []struct {
		device generated.Device
		events []*pb.DeviceEvent
	}
}

func (f *fakeEventsRecorder) IngestBatch(ctx context.Context, device generated.Device, events []*pb.DeviceEvent) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.calls = append(f.calls, struct {
		device generated.Device
		events []*pb.DeviceEvent
	}{device: device, events: events})
	return len(events), nil
}

func (f *fakeDeviceStore) GetTenantByCode(ctx context.Context, tenantCode string) (generated.Tenant, error) {
	if f.getTenantByCodeFn != nil {
		return f.getTenantByCodeFn(ctx, tenantCode)
	}
	return generated.Tenant{}, errors.New("not implemented")
}

func (f *fakeDeviceStore) CreateDevice(ctx context.Context, arg generated.CreateDeviceParams) (generated.Device, error) {
	if f.createDeviceFn != nil {
		return f.createDeviceFn(ctx, arg)
	}
	return generated.Device{}, errors.New("not implemented")
}

func (f *fakeDeviceStore) GetDeviceByID(ctx context.Context, deviceID string) (generated.Device, error) {
	if f.getDeviceByIDFn != nil {
		return f.getDeviceByIDFn(ctx, deviceID)
	}
	return generated.Device{}, errors.New("not implemented")
}

func (f *fakeDeviceStore) UpdateDeviceLastSeen(ctx context.Context, arg generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
	if f.updateDeviceLastSeenFn != nil {
		return f.updateDeviceLastSeenFn(ctx, arg)
	}
	return generated.Device{}, nil
}

func (f *fakeDeviceStore) UpsertDeviceState(ctx context.Context, arg generated.UpsertDeviceStateParams) (generated.DeviceState, error) {
	if f.upsertDeviceStateFn != nil {
		return f.upsertDeviceStateFn(ctx, arg)
	}
	return generated.DeviceState{}, nil
}

func (f *fakeDeviceStore) GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (generated.Policy, error) {
	if f.getLatestPolicyTenantFn != nil {
		return f.getLatestPolicyTenantFn(ctx, tenantID)
	}
	return generated.Policy{}, errors.New("not implemented")
}

func (f *fakeDeviceStore) GetDeviceBySerialNumber(ctx context.Context, serial *string) (generated.Device, error) {
	if f.getDeviceBySerialFn != nil {
		return f.getDeviceBySerialFn(ctx, serial)
	}
	return generated.Device{}, pgx.ErrNoRows
}

type fakePolicyService struct {
	latestPolicyFn func(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error)
	defaultPolicy  *pb.PolicyBundle
}

func (f *fakePolicyService) GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
	if f.latestPolicyFn != nil {
		return f.latestPolicyFn(ctx, tenantID)
	}
	return nil, errors.New("no policy")
}

func (f *fakePolicyService) GetDefaultPolicy() *pb.PolicyBundle {
	if f.defaultPolicy != nil {
		return f.defaultPolicy
	}
	return &pb.PolicyBundle{}
}

func newDeviceTokenManager(t *testing.T) *auth.Manager {
	t.Helper()
	secret := []byte("abcdefghijklmnopqrstuvwxyz123456")
	mgr, err := auth.NewManager(secret, time.Hour, 4*time.Hour)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	mgr.WithBcryptCost(4)
	return mgr
}

func TestPullPolicyReturnsLatestBundleWhenOutdated(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(uuid.New().String())

	tokenManager := newDeviceTokenManager(t)

	expectedPolicy := &pb.PolicyBundle{
		Id:      "policy-123",
		Name:    "Test Policy",
		Version: timestamppb.New(now),
	}

	deviceID := "device-1"
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken(deviceID, tenantUUID.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	device := generated.Device{TenantID: tenantUUID, DeviceTokenHash: hashedToken}
	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			return device, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, arg generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			if arg.DeviceID != deviceID {
				t.Fatalf("unexpected device id %s", arg.DeviceID)
			}
			if !arg.LastSeenAt.Valid {
				t.Fatal("last seen timestamp should be valid")
			}
			return generated.Device{}, nil
		},
	}

	policySvc := &fakePolicyService{
		latestPolicyFn: func(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
			if tenantID != tenantUUID {
				t.Fatalf("unexpected tenant id: %v", tenantID)
			}
			return expectedPolicy, nil
		},
	}

	service := NewDeviceServiceWithDependencies(store, policySvc, tokenManager, &fakeEventsRecorder{}, nil)

	req := &pb.PullPolicyRequest{
		DeviceId:             deviceID,
		DeviceToken:          rawToken,
		CurrentPolicyVersion: timestamppb.New(now.Add(-time.Hour)),
		RequestTime:          timestamppb.New(now),
	}

	resp, err := service.PullPolicy(context.Background(), req)
	if err != nil {
		t.Fatalf("PullPolicy returned error: %v", err)
	}

	if !resp.PolicyUpdated {
		t.Fatalf("expected policy update, got %#v", resp)
	}

	if resp.PolicyBundle == nil {
		t.Fatal("expected policy bundle to be returned")
	}

	if resp.PolicyBundle.Id != expectedPolicy.Id {
		t.Fatalf("unexpected policy bundle: %#v", resp.PolicyBundle)
	}

	if resp.ServerTime == nil || resp.NextCheckin == nil {
		t.Fatal("expected timing fields to be populated")
	}

	diff := resp.NextCheckin.AsTime().Sub(resp.ServerTime.AsTime())
	if diff < 5*time.Minute-10*time.Second || diff > 5*time.Minute+10*time.Second {
		t.Fatalf("expected next check-in approximately 5 minutes, got %s", diff)
	}
}

func TestPullPolicySkipsUpdateWhenVersionCurrent(t *testing.T) {
	t.Parallel()

	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(uuid.New().String())

	now := time.Now()
	policy := &pb.PolicyBundle{Version: timestamppb.New(now)}

	tokenManager := newDeviceTokenManager(t)
	deviceID := "device-1"
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken(deviceID, tenantUUID.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			return generated.Device{TenantID: tenantUUID, DeviceTokenHash: hashedToken}, nil
		},
	}

	policySvc := &fakePolicyService{
		latestPolicyFn: func(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
			return policy, nil
		},
	}

	service := NewDeviceServiceWithDependencies(store, policySvc, tokenManager, &fakeEventsRecorder{}, nil)

	req := &pb.PullPolicyRequest{
		DeviceId:             deviceID,
		DeviceToken:          rawToken,
		CurrentPolicyVersion: timestamppb.New(now),
		RequestTime:          timestamppb.New(now),
	}

	resp, err := service.PullPolicy(context.Background(), req)
	if err != nil {
		t.Fatalf("PullPolicy returned error: %v", err)
	}

	if resp.PolicyUpdated {
		t.Fatal("did not expect policy update when versions match")
	}

	if resp.PolicyBundle != nil {
		t.Fatal("expected policy bundle to be nil when no update")
	}
}

func TestPullPolicyRejectsInvalidRequest(t *testing.T) {
	t.Parallel()

	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.PullPolicy(context.Background(), &pb.PullPolicyRequest{})
	if err == nil {
		t.Fatal("expected error for invalid request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}

	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestPullPolicyRejectsUnknownDevice(t *testing.T) {
	t.Parallel()

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			return generated.Device{}, errors.New("not found")
		},
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	req := &pb.PullPolicyRequest{
		DeviceId:    "device-404",
		DeviceToken: "token",
		RequestTime: timestamppb.Now(),
	}

	_, err := service.PullPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown device")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status, got %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %s", st.Code())
	}
}
