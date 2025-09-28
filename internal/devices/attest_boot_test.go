package devices

import (
	"context"
	"errors"
	"testing"
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

type fakeAttestor struct {
	calls []attestation.Quote
	err   error
}

func (f *fakeAttestor) Verify(q attestation.Quote) error {
	f.calls = append(f.calls, q)
	return f.err
}

func TestAttestBootSuccess(t *testing.T) {
	t.Parallel()

	tenant := uuid.New()
	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(tenant.String())

	tokenManager := newDeviceTokenManager(t)
	deviceID := "device-123"
	token, hash, err := tokenManager.IssueDeviceToken(deviceID, tenant.String())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	var updated bool
	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, id string) (generated.Device, error) {
			if id != deviceID {
				return generated.Device{}, errors.New("unexpected device id")
			}
			return generated.Device{DeviceID: deviceID, DeviceTokenHash: hash, TenantID: tenantUUID}, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, params generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			if params.DeviceID != deviceID {
				t.Fatalf("unexpected device id %s", params.DeviceID)
			}
			if !params.LastSeenAt.Valid {
				t.Fatalf("expected valid timestamp")
			}
			updated = true
			return generated.Device{}, nil
		},
	}

	attestor := &fakeAttestor{}
	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, &fakeEventsRecorder{}, attestor)

	req := &pb.AttestBootRequest{
		DeviceId:      deviceID,
		DeviceToken:   token,
		Nonce:         "nonce",
		ExpectedNonce: "nonce",
		Quote:         []byte("quote"),
		Signature:     []byte("quote"),
		ProducedAt:    timestamppb.New(time.Now()),
	}

	resp, err := service.AttestBoot(context.Background(), req)
	if err != nil {
		t.Fatalf("AttestBoot returned error: %v", err)
	}
	if !resp.Verified {
		t.Fatalf("expected attestation to be verified")
	}
	if len(attestor.calls) != 1 {
		t.Fatalf("expected attestor to be invoked once, got %d", len(attestor.calls))
	}
	if attestor.calls[0].Nonce != "nonce" {
		t.Fatalf("expected nonce to be forwarded")
	}
	if !updated {
		t.Fatal("expected device last seen to be updated")
	}
}

func TestAttestBootValidatesRequest(t *testing.T) {
	t.Parallel()
	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, &fakeAttestor{})
	_, err := service.AttestBoot(context.Background(), &pb.AttestBootRequest{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestAttestBootPropagatesVerifierError(t *testing.T) {
	t.Parallel()

	tenant := uuid.New()
	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(tenant.String())
	tokenManager := newDeviceTokenManager(t)
	deviceID := "device-err"
	token, hash, err := tokenManager.IssueDeviceToken(deviceID, tenant.String())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, id string) (generated.Device, error) {
			return generated.Device{DeviceID: deviceID, DeviceTokenHash: hash, TenantID: tenantUUID}, nil
		},
	}

	attestor := &fakeAttestor{err: errors.New("invalid quote")}
	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, &fakeEventsRecorder{}, attestor)

	req := &pb.AttestBootRequest{
		DeviceId:      deviceID,
		DeviceToken:   token,
		Nonce:         "nonce",
		ExpectedNonce: "nonce",
		Quote:         []byte("quote"),
		Signature:     []byte("quote"),
		ProducedAt:    timestamppb.Now(),
	}

	_, err = service.AttestBoot(context.Background(), req)
	if err == nil {
		t.Fatal("expected verifier error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", st.Code())
	}
}

func TestAttestBootDisabled(t *testing.T) {
	t.Parallel()

	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.AttestBoot(context.Background(), &pb.AttestBootRequest{DeviceId: "d", DeviceToken: "t"})
	if err == nil {
		t.Fatal("expected unimplemented error when attestation disabled")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected unimplemented, got %v", st.Code())
	}
}
