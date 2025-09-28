package tenants

import (
	"context"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/audit"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeTenantStore struct {
	tenants map[string]generated.Tenant
}

func newFakeTenantStore() *fakeTenantStore {
	return &fakeTenantStore{tenants: make(map[string]generated.Tenant)}
}

func (f *fakeTenantStore) CreateTenant(ctx context.Context, arg generated.CreateTenantParams) (generated.Tenant, error) {
	id := uuid.New()
	tenant := generated.Tenant{
		ID:         uuidToPG(id),
		TenantCode: arg.TenantCode,
		Name:       arg.Name,
		CreatedAt:  pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt:  pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	f.tenants[id.String()] = tenant
	return tenant, nil
}

func (f *fakeTenantStore) ListTenants(ctx context.Context, arg generated.ListTenantsParams) ([]generated.Tenant, error) {
	tenants := make([]generated.Tenant, 0, len(f.tenants))
	for _, tenant := range f.tenants {
		tenants = append(tenants, tenant)
	}
	start := int(arg.Offset)
	if start > len(tenants) {
		return []generated.Tenant{}, nil
	}
	end := start + int(arg.Limit)
	if arg.Limit <= 0 || end > len(tenants) {
		end = len(tenants)
	}
	return tenants[start:end], nil
}

func (f *fakeTenantStore) UpdateTenantSecret(ctx context.Context, arg generated.UpdateTenantSecretParams) (generated.Tenant, error) {
	for key, tenant := range f.tenants {
		if tenant.ID == arg.ID {
			tenant.EnrollmentSecretHash = arg.EnrollmentSecretHash
			tenant.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
			f.tenants[key] = tenant
			return tenant, nil
		}
	}
	return generated.Tenant{}, status.Error(codes.NotFound, "tenant not found")
}

func (f *fakeTenantStore) GetTenantByID(ctx context.Context, id pgtype.UUID) (generated.Tenant, error) {
	for _, tenant := range f.tenants {
		if tenant.ID == id {
			return tenant, nil
		}
	}
	return generated.Tenant{}, status.Error(codes.NotFound, "tenant not found")
}

type fakeTenantAuditor struct {
	entries []audit.Entry
}

func (f *fakeTenantAuditor) Record(ctx context.Context, entry audit.Entry) error {
	f.entries = append(f.entries, entry)
	return nil
}

func TestServiceCreateTenant(t *testing.T) {
	ctx := context.Background()
	store := newFakeTenantStore()
	auditor := &fakeTenantAuditor{}
	svc := NewService(store, mustManager(t), auditor)
	actor := &auth.AdminClaims{Subject: uuid.New().String(), Role: roleOwner}
	resp, err := svc.CreateTenantWithClaims(ctx, actor, &pb.CreateTenantRequest{TenantCode: "code", Name: "School", EnrollmentSecret: "secret123"})
	if err != nil {
		t.Fatalf("CreateTenantWithClaims: %v", err)
	}
	if resp.Tenant == nil || resp.Tenant.Id == "" {
		t.Fatalf("expected tenant id")
	}
	record := store.tenants[resp.Tenant.Id]
	if record.EnrollmentSecretHash == "" {
		t.Fatalf("expected hashed secret")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(record.EnrollmentSecretHash), []byte("secret123")); err != nil {
		t.Fatalf("secret not hashed correctly: %v", err)
	}
	if len(auditor.entries) != 1 {
		t.Fatalf("expected audit entry")
	}
}

func TestServiceRotateTenantSecret(t *testing.T) {
	ctx := context.Background()
	store := newFakeTenantStore()
	svc := NewService(store, mustManager(t), &fakeTenantAuditor{})
	actor := &auth.AdminClaims{Subject: uuid.New().String(), Role: roleOwner}
	created, err := svc.CreateTenantWithClaims(ctx, actor, &pb.CreateTenantRequest{TenantCode: "code", Name: "Org", EnrollmentSecret: "initial"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	_, err = svc.RotateTenantSecretWithClaims(ctx, actor, &pb.RotateTenantSecretRequest{TenantId: created.Tenant.Id, EnrollmentSecret: "rotated"})
	if err != nil {
		t.Fatalf("RotateTenantSecretWithClaims: %v", err)
	}
	record := store.tenants[created.Tenant.Id]
	if err := bcrypt.CompareHashAndPassword([]byte(record.EnrollmentSecretHash), []byte("rotated")); err != nil {
		t.Fatalf("rotation did not update hash: %v", err)
	}
}

func TestServiceCreateTenantRequiresMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	svc := NewService(newFakeTenantStore(), mustManager(t), nil)
	if _, err := svc.CreateTenant(ctx, &pb.CreateTenantRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func mustManager(t *testing.T) *auth.Manager {
	t.Helper()
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	return mgr
}
