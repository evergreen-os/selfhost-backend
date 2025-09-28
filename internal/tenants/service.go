package tenants

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	roleOwner   = "owner"
	roleAdmin   = "admin"
	roleAuditor = "auditor"
)

// Store captures the persistence operations required by the tenant service.
type Store interface {
	CreateTenant(ctx context.Context, arg generated.CreateTenantParams) (generated.Tenant, error)
	ListTenants(ctx context.Context, arg generated.ListTenantsParams) ([]generated.Tenant, error)
	UpdateTenantSecret(ctx context.Context, arg generated.UpdateTenantSecretParams) (generated.Tenant, error)
	GetTenantByID(ctx context.Context, id pgtype.UUID) (generated.Tenant, error)
}

type auditor interface {
	Record(ctx context.Context, entry audit.Entry) error
}

// Service exposes tenant management operations across gRPC and REST.
type Service struct {
	pb.UnimplementedTenantServiceServer

	store   Store
	tokens  *auth.Manager
	auditor auditor
	now     func() time.Time
}

// NewService constructs a tenant service with the provided dependencies.
func NewService(store Store, tokens *auth.Manager, auditor auditor) *Service {
	return &Service{store: store, tokens: tokens, auditor: auditor, now: time.Now}
}

// CreateTenant authenticates via metadata then delegates to CreateTenantWithClaims.
func (s *Service) CreateTenant(ctx context.Context, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreateTenantWithClaims(ctx, claims, req)
}

// CreateTenantWithClaims provisions a new tenant and enrollment secret.
func (s *Service) CreateTenantWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner) {
		return nil, status.Error(codes.PermissionDenied, "owner role required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	code := strings.TrimSpace(req.TenantCode)
	name := strings.TrimSpace(req.Name)
	secret := strings.TrimSpace(req.EnrollmentSecret)
	if code == "" || name == "" || secret == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_code, name, and enrollment_secret are required")
	}
	if s.store == nil {
		return nil, status.Error(codes.Internal, "tenant store not configured")
	}
	created, err := s.store.CreateTenant(ctx, generated.CreateTenantParams{TenantCode: code, Name: name})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create tenant: %v", err)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash enrollment secret: %v", err)
	}
	updated, err := s.store.UpdateTenantSecret(ctx, generated.UpdateTenantSecretParams{ID: created.ID, EnrollmentSecretHash: string(hashed)})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store enrollment secret: %v", err)
	}
	tenantUUID, _ := uuid.FromBytes(updated.ID.Bytes[:])
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			TenantID:     &tenantUUID,
			Action:       "tenant.create",
			ResourceType: "tenant",
			ResourceID:   tenantUUID.String(),
			OccurredAt:   s.now().UTC(),
			Details: map[string]any{
				"tenant_code": updated.TenantCode,
				"name":        updated.Name,
			},
		})
	}
	return &pb.CreateTenantResponse{Tenant: toPBTenant(updated)}, nil
}

// ListTenants authenticates via metadata then delegates to ListTenantsWithClaims.
func (s *Service) ListTenants(ctx context.Context, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListTenantsWithClaims(ctx, claims, req)
}

// ListTenantsWithClaims returns tenants visible to the admin.
func (s *Service) ListTenantsWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin, roleAuditor) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if s.store == nil {
		return nil, status.Error(codes.Internal, "tenant store not configured")
	}
	limit := req.PageSize
	if limit <= 0 {
		limit = 50
	}
	offset := int32(0)
	if token := strings.TrimSpace(req.PageToken); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
		offset = int32(parsed)
	}
	records, err := s.store.ListTenants(ctx, generated.ListTenantsParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tenants: %v", err)
	}
	tenants := make([]*pb.Tenant, 0, len(records))
	for _, tenant := range records {
		tenants = append(tenants, toPBTenant(tenant))
	}
	next := ""
	if int32(len(records)) == limit {
		next = fmt.Sprintf("%d", offset+limit)
	}
	return &pb.ListTenantsResponse{Tenants: tenants, NextPageToken: next}, nil
}

// RotateTenantSecret authenticates via metadata then delegates to RotateTenantSecretWithClaims.
func (s *Service) RotateTenantSecret(ctx context.Context, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.RotateTenantSecretWithClaims(ctx, claims, req)
}

// RotateTenantSecretWithClaims rotates the enrollment secret for a tenant.
func (s *Service) RotateTenantSecretWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner) {
		return nil, status.Error(codes.PermissionDenied, "owner role required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	tenantID := strings.TrimSpace(req.TenantId)
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant id is required")
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "tenant id invalid")
	}
	secret := strings.TrimSpace(req.EnrollmentSecret)
	if secret == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment secret is required")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash enrollment secret: %v", err)
	}
	updated, err := s.store.UpdateTenantSecret(ctx, generated.UpdateTenantSecretParams{ID: uuidToPG(tenantUUID), EnrollmentSecretHash: string(hashed)})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update enrollment secret: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			TenantID:     &tenantUUID,
			Action:       "tenant.rotate_secret",
			ResourceType: "tenant",
			ResourceID:   tenantUUID.String(),
			OccurredAt:   s.now().UTC(),
		})
	}
	return &pb.RotateTenantSecretResponse{Tenant: toPBTenant(updated)}, nil
}

func (s *Service) claimsFromContext(ctx context.Context) (*auth.AdminClaims, error) {
	if s.tokens == nil {
		return nil, status.Error(codes.Internal, "token manager not configured")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authorization metadata required")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization metadata required")
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, status.Error(codes.Unauthenticated, "bearer token required")
	}
	claims, err := s.tokens.ParseAdminToken(parts[1])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid admin token")
	}
	return claims, nil
}

func toPBTenant(record generated.Tenant) *pb.Tenant {
	tenant := &pb.Tenant{
		Id:         uuidString(record.ID),
		TenantCode: record.TenantCode,
		Name:       record.Name,
	}
	if record.CreatedAt.Valid {
		tenant.CreatedAt = timestamppb.New(record.CreatedAt.Time)
	}
	if record.UpdatedAt.Valid {
		tenant.UpdatedAt = timestamppb.New(record.UpdatedAt.Time)
	}
	return tenant
}

func uuidString(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	id, err := uuid.FromBytes(value.Bytes[:])
	if err != nil {
		return ""
	}
	return id.String()
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	var out pgtype.UUID
	out.Valid = true
	copy(out.Bytes[:], id[:])
	return out
}

func hasRole(role string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(role, candidate) {
			return true
		}
	}
	return false
}
