package policies

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/audit"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	roleOwner   = "owner"
	roleAdmin   = "admin"
	roleAuditor = "auditor"
)

// AdminAPI exposes policy CRUD for REST translation.
type AdminAPI interface {
	CreatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error)
	UpdatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error)
	DeletePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error)
	GetPolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error)
	ListPoliciesWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error)
}

type auditor interface {
	Record(ctx context.Context, entry audit.Entry) error
}

// AdminService implements Evergreen policy management workflows across gRPC and REST.
type AdminService struct {
	pb.UnimplementedPolicyServiceServer

	policies *PolicyService
	tokens   *auth.Manager
	auditor  auditor
	now      func() time.Time
}

// NewAdminService constructs a policy admin service.
func NewAdminService(policies *PolicyService, tokens *auth.Manager, auditor auditor) *AdminService {
	return &AdminService{
		policies: policies,
		tokens:   tokens,
		auditor:  auditor,
		now:      time.Now,
	}
}

// CreatePolicy authenticates the caller from gRPC metadata before delegating to CreatePolicyWithClaims.
func (s *AdminService) CreatePolicy(ctx context.Context, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreatePolicyWithClaims(ctx, claims, req)
}

// CreatePolicyWithClaims provisions a new policy bundle for the actor's tenant.
func (s *AdminService) CreatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if req == nil || req.Policy == nil {
		return nil, status.Error(codes.InvalidArgument, "policy request is required")
	}
	tenantUUID, err := s.resolveTenant(actor, req.TenantId)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Policy.Name)
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "policy name is required")
	}
	created, err := s.policies.CreatePolicyBundle(ctx, uuidToPG(tenantUUID), name, req.Policy, actor.Subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create policy: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			TenantID:     &tenantUUID,
			Action:       "policy.create",
			ResourceType: "policy",
			ResourceID:   created.Id,
			OccurredAt:   s.now().UTC(),
			Details: map[string]any{
				"name": created.Name,
			},
		})
	}
	return &pb.CreatePolicyResponse{Policy: created}, nil
}

// UpdatePolicy authenticates via gRPC metadata then delegates to UpdatePolicyWithClaims.
func (s *AdminService) UpdatePolicy(ctx context.Context, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.UpdatePolicyWithClaims(ctx, claims, req)
}

// UpdatePolicyWithClaims updates an existing policy bundle.
func (s *AdminService) UpdatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if req == nil || req.Policy == nil {
		return nil, status.Error(codes.InvalidArgument, "policy request is required")
	}
	if strings.TrimSpace(req.PolicyId) == "" {
		return nil, status.Error(codes.InvalidArgument, "policy id is required")
	}
	updated, err := s.policies.UpdatePolicyBundle(ctx, req.PolicyId, strings.TrimSpace(req.Name), req.Policy, actor.Subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update policy: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			TenantID:     nil,
			Action:       "policy.update",
			ResourceType: "policy",
			ResourceID:   updated.Id,
			OccurredAt:   s.now().UTC(),
			Details: map[string]any{
				"name": updated.Name,
			},
		})
	}
	return &pb.UpdatePolicyResponse{Policy: updated}, nil
}

// DeletePolicy enforces gRPC authentication via metadata.
func (s *AdminService) DeletePolicy(ctx context.Context, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.DeletePolicyWithClaims(ctx, claims, req)
}

// DeletePolicyWithClaims removes a policy bundle.
func (s *AdminService) DeletePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if req == nil || strings.TrimSpace(req.PolicyId) == "" {
		return nil, status.Error(codes.InvalidArgument, "policy id is required")
	}
	if err := s.policies.DeletePolicyBundle(ctx, strings.TrimSpace(req.PolicyId), actor.Subject); err != nil {
		return nil, status.Errorf(codes.Internal, "delete policy: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			Action:       "policy.delete",
			ResourceType: "policy",
			ResourceID:   strings.TrimSpace(req.PolicyId),
			OccurredAt:   s.now().UTC(),
		})
	}
	return &pb.DeletePolicyResponse{}, nil
}

// GetPolicy enforces gRPC authentication and delegates to GetPolicyWithClaims.
func (s *AdminService) GetPolicy(ctx context.Context, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetPolicyWithClaims(ctx, claims, req)
}

// GetPolicyWithClaims fetches a single policy bundle.
func (s *AdminService) GetPolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin, roleAuditor) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if req == nil || strings.TrimSpace(req.PolicyId) == "" {
		return nil, status.Error(codes.InvalidArgument, "policy id is required")
	}
	policy, err := s.policies.GetPolicyByID(ctx, strings.TrimSpace(req.PolicyId))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get policy: %v", err)
	}
	return &pb.GetPolicyResponse{Policy: policy}, nil
}

// ListPolicies enforces metadata authentication.
func (s *AdminService) ListPolicies(ctx context.Context, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListPoliciesWithClaims(ctx, claims, req)
}

// ListPoliciesWithClaims lists policies for the tenant.
func (s *AdminService) ListPoliciesWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin, roleAuditor) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	tenantUUID, err := s.resolveTenant(actor, req.TenantId)
	if err != nil {
		return nil, err
	}
	limit := req.PageSize
	if limit <= 0 {
		limit = 25
	}
	offset := int32(0)
	if strings.TrimSpace(req.PageToken) != "" {
		parsed, err := strconv.Atoi(req.PageToken)
		if err != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
		offset = int32(parsed)
	}
	policies, err := s.policies.ListPolicyBundles(ctx, uuidToPG(tenantUUID), limit, offset)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list policies: %v", err)
	}
	next := ""
	if int32(len(policies)) == limit {
		next = fmt.Sprintf("%d", offset+limit)
	}
	return &pb.ListPoliciesResponse{Policies: policies, NextPageToken: next}, nil
}

func (s *AdminService) claimsFromContext(ctx context.Context) (*auth.AdminClaims, error) {
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

func (s *AdminService) resolveTenant(actor *auth.AdminClaims, requested string) (uuid.UUID, error) {
	tenantID := strings.TrimSpace(requested)
	if tenantID == "" {
		tenantID = actor.TenantID
	}
	if tenantID == "" {
		return uuid.UUID{}, status.Error(codes.InvalidArgument, "tenant id is required")
	}
	if !strings.EqualFold(tenantID, actor.TenantID) {
		return uuid.UUID{}, status.Error(codes.PermissionDenied, "cannot manage other tenants")
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return uuid.UUID{}, status.Error(codes.InvalidArgument, "tenant id invalid")
	}
	return tenantUUID, nil
}

func hasRole(role string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(role, candidate) {
			return true
		}
	}
	return false
}
