package devices

import (
	"context"
	"errors"
	"testing"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validEnrollmentRequest() *pb.EnrollDeviceRequest {
	return &pb.EnrollDeviceRequest{
		EnrollmentToken:  "tenant-code",
		EnrollmentSecret: "secret",
		Hardware: &pb.HardwareInfo{
			Model:             "Evergreen Model",
			Manufacturer:      "Evergreen",
			SerialNumber:      "SN123",
			Architecture:      pb.Architecture_ARCHITECTURE_X86_64,
			TotalMemoryBytes:  8 * 1024 * 1024 * 1024,
			TotalStorageBytes: 128 * 1024 * 1024 * 1024,
		},
		OsInfo: &pb.OSInfo{
			Name:          "EvergreenOS",
			Version:       "1.0",
			KernelVersion: "6.0",
			BuildId:       "build-123",
		},
		Network: &pb.NetworkInfo{
			Hostname:          "device.local",
			PrimaryMacAddress: "00:11:22:33:44:55",
		},
		AgentVersion: &pb.Version{Version: "1.2.3", Commit: "abc123", BuildTime: timestamppb.Now()},
		Nonce:        "nonce-value",
	}
}

func TestEnrollDeviceSuccess(t *testing.T) {
	t.Parallel()

	tenantUUID := pgtype.UUID{}
	_ = tenantUUID.Scan(uuid.New().String())

	tokenManager := newDeviceTokenManager(t)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	policy := &pb.PolicyBundle{Id: "policy-1", Name: "Default", Version: timestamppb.Now()}

	var capturedHash string
	store := &fakeDeviceStore{
		getTenantByCodeFn: func(ctx context.Context, tenantCode string) (generated.Tenant, error) {
			if tenantCode != "tenant-code" {
				return generated.Tenant{}, errors.New("unexpected tenant code")
			}
			return generated.Tenant{ID: tenantUUID, TenantCode: tenantCode, EnrollmentSecretHash: string(hashedSecret)}, nil
		},
		createDeviceFn: func(ctx context.Context, arg generated.CreateDeviceParams) (generated.Device, error) {
			capturedHash = arg.DeviceTokenHash
			if arg.Status != "enrolled" {
				t.Fatalf("expected status enrolled, got %s", arg.Status)
			}
			return generated.Device{DeviceID: arg.DeviceID}, nil
		},
	}

	policySvc := &fakePolicyService{
		latestPolicyFn: func(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
			return policy, nil
		},
	}

	service := NewDeviceServiceWithDependencies(store, policySvc, tokenManager, &fakeEventsRecorder{}, nil)

	req := validEnrollmentRequest()
	resp, err := service.EnrollDevice(context.Background(), req)
	if err != nil {
		t.Fatalf("EnrollDevice returned error: %v", err)
	}

	if resp.DeviceId == "" {
		t.Fatal("expected device id to be set")
	}
	if resp.DeviceToken == "" {
		t.Fatal("expected device token to be returned")
	}
	if resp.PolicyBundle == nil || resp.PolicyBundle.Id != policy.Id {
		t.Fatalf("expected policy bundle %s", policy.Id)
	}
	if capturedHash == "" {
		t.Fatal("expected hashed token to be stored")
	}

	tenantUUIDParsed, _ := uuid.FromBytes(tenantUUID.Bytes[:])
	if _, err := tokenManager.VerifyDeviceToken(resp.DeviceToken, resp.DeviceId, tenantUUIDParsed.String(), capturedHash); err != nil {
		t.Fatalf("device token verification failed: %v", err)
	}
}

func TestEnrollDeviceValidatesRequest(t *testing.T) {
	t.Parallel()

	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestEnrollDeviceRejectsUnknownTenant(t *testing.T) {
	t.Parallel()

	store := &fakeDeviceStore{
		getTenantByCodeFn: func(ctx context.Context, tenantCode string) (generated.Tenant, error) {
			return generated.Tenant{}, errors.New("not found")
		},
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.EnrollDevice(context.Background(), validEnrollmentRequest())
	if err == nil {
		t.Fatal("expected tenant validation error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated error, got %v", err)
	}
}

func TestEnrollDeviceRejectsInvalidSecret(t *testing.T) {
	t.Parallel()

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	store := &fakeDeviceStore{
		getTenantByCodeFn: func(ctx context.Context, tenantCode string) (generated.Tenant, error) {
			return generated.Tenant{EnrollmentSecretHash: string(hashedSecret)}, nil
		},
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)
	req := validEnrollmentRequest()
	req.EnrollmentSecret = "wrong"
	_, err = service.EnrollDevice(context.Background(), req)
	if err == nil {
		t.Fatal("expected secret validation error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", st.Code())
	}
}

func TestEnrollDeviceRejectsDuplicateSerial(t *testing.T) {
	t.Parallel()

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	store := &fakeDeviceStore{
		getTenantByCodeFn: func(ctx context.Context, tenantCode string) (generated.Tenant, error) {
			return generated.Tenant{EnrollmentSecretHash: string(hashedSecret)}, nil
		},
		getDeviceBySerialFn: func(ctx context.Context, serial *string) (generated.Device, error) {
			return generated.Device{DeviceID: "existing"}, nil
		},
	}

	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)
	_, err = service.EnrollDevice(context.Background(), validEnrollmentRequest())
	if err == nil {
		t.Fatal("expected duplicate device error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("expected already exists, got %v", st.Code())
	}
}
