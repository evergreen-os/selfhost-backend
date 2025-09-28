package admin

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

// Store captures the persistence operations required by the admin service.
type Store interface {
	GetUserByUsername(ctx context.Context, username string) (generated.User, error)
	UpdateUserLastLogin(ctx context.Context, id pgtype.UUID) (generated.User, error)
	CreateUser(ctx context.Context, params generated.CreateUserParams) (generated.User, error)
	ListUsersByTenant(ctx context.Context, params generated.ListUsersByTenantParams) ([]generated.User, error)
	GetTenantByID(ctx context.Context, id pgtype.UUID) (generated.Tenant, error)
}

// Auditor records immutable audit events.
type Auditor interface {
	Record(ctx context.Context, entry audit.Entry) error
}

// Service implements Evergreen admin workflows across gRPC and REST layers.
type Service struct {
	pb.UnimplementedAdminServiceServer

	store   Store
	tokens  *auth.Manager
	auditor Auditor
	now     func() time.Time
}

// NewService constructs an admin service with the provided dependencies.
func NewService(store Store, tokens *auth.Manager, auditor Auditor) *Service {
	return &Service{
		store:   store,
		tokens:  tokens,
		auditor: auditor,
		now:     time.Now,
	}
}

// Login authenticates a console user and issues a signed JWT.
func (s *Service) Login(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}
	user, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	updated, err := s.store.UpdateUserLastLogin(ctx, user.ID)
	if err == nil {
		user = updated
	}
	tenantUUID, err := uuidFromPG(user.TenantID)
	if err != nil {
		return nil, status.Error(codes.Internal, "user tenant invalid")
	}
	userUUID, err := uuidFromPG(user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "user id invalid")
	}
	token, err := s.tokens.IssueAdminToken(userUUID.String(), tenantUUID.String(), user.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue token: %v", err)
	}
	claims, err := s.tokens.ParseAdminToken(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "parse token: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:  "user",
			ActorID:    userUUID.String(),
			TenantID:   &tenantUUID,
			Action:     "admin.login",
			OccurredAt: s.now().UTC(),
		})
	}
	return &pb.AdminLoginResponse{
		AccessToken: token,
		ExpiresAt:   timestamppb.New(claims.ExpiresAt),
		User:        toPBUser(user),
	}, nil
}

// CreateUser implements the gRPC admin service by extracting claims from metadata.
func (s *Service) CreateUser(ctx context.Context, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreateUserWithClaims(ctx, claims, req)
}

// CreateUserWithClaims provisions a new admin account for a tenant.
func (s *Service) CreateUserWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner) {
		return nil, status.Error(codes.PermissionDenied, "owner role required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	targetTenant := strings.TrimSpace(req.TenantId)
	if targetTenant == "" {
		targetTenant = actor.TenantID
	}
	if targetTenant == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant id is required")
	}
	if targetTenant != actor.TenantID {
		return nil, status.Error(codes.PermissionDenied, "cannot manage other tenants")
	}
	tenantUUID, err := uuid.Parse(targetTenant)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "tenant id invalid")
	}
	tenantPG := uuidToPG(tenantUUID)
	if _, err := s.store.GetTenantByID(ctx, tenantPG); err != nil {
		return nil, status.Error(codes.InvalidArgument, "tenant not found")
	}
	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	if username == "" || email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username, email, and password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash password: %v", err)
	}
	role, err := storeRole(req.Role)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	created, err := s.store.CreateUser(ctx, generated.CreateUserParams{
		TenantID:     tenantPG,
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		Role:         role,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create user: %v", err)
	}
	if s.auditor != nil {
		_ = s.auditor.Record(ctx, audit.Entry{
			ActorType:    "user",
			ActorID:      actor.Subject,
			TenantID:     &tenantUUID,
			Action:       "admin.user.create",
			ResourceType: "user",
			ResourceID:   uuidString(created.ID),
			OccurredAt:   s.now().UTC(),
			Details: map[string]any{
				"username": created.Username,
				"role":     created.Role,
			},
		})
	}
	return &pb.CreateAdminUserResponse{User: toPBUser(created)}, nil
}

// ListUsers implements the gRPC admin service with metadata-based authentication.
func (s *Service) ListUsers(ctx context.Context, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error) {
	claims, err := s.claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListUsersWithClaims(ctx, claims, req)
}

// ListUsersWithClaims returns a page of admin users scoped to the actor's tenant.
func (s *Service) ListUsersWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error) {
	if actor == nil {
		return nil, status.Error(codes.Unauthenticated, "admin authentication required")
	}
	if !hasRole(actor.Role, roleOwner, roleAdmin, roleAuditor) {
		return nil, status.Error(codes.PermissionDenied, "insufficient role")
	}
	if req == nil {
		req = &pb.ListAdminUsersRequest{}
	}
	tenantID := strings.TrimSpace(req.TenantId)
	if tenantID == "" {
		tenantID = actor.TenantID
	}
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant id is required")
	}
	if tenantID != actor.TenantID {
		return nil, status.Error(codes.PermissionDenied, "cannot view other tenants")
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "tenant id invalid")
	}
	limit := req.PageSize
	if limit <= 0 {
		limit = 50
	}
	offset := int32(0)
	if req.PageToken != "" {
		parsed, err := strconv.Atoi(req.PageToken)
		if err != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
		offset = int32(parsed)
	}
	results, err := s.store.ListUsersByTenant(ctx, generated.ListUsersByTenantParams{
		TenantID: uuidToPG(tenantUUID),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list users: %v", err)
	}
	users := make([]*pb.AdminUser, 0, len(results))
	for _, user := range results {
		users = append(users, toPBUser(user))
	}
	nextToken := ""
	if int32(len(results)) == limit {
		nextToken = fmt.Sprintf("%d", offset+limit)
	}
	return &pb.ListAdminUsersResponse{Users: users, NextPageToken: nextToken}, nil
}

func toPBUser(user generated.User) *pb.AdminUser {
	idStr := uuidString(user.ID)
	tenantStr := uuidString(user.TenantID)
	return &pb.AdminUser{
		Id:          idStr,
		TenantId:    tenantStr,
		Username:    user.Username,
		Email:       user.Email,
		Role:        pbRole(user.Role),
		CreatedAt:   timestamppbOrNil(user.CreatedAt),
		UpdatedAt:   timestamppbOrNil(user.UpdatedAt),
		LastLoginAt: timestamppbOrNil(user.LastLoginAt),
	}
}

func pbRole(role string) pb.AdminRole {
	switch strings.ToLower(role) {
	case roleOwner:
		return pb.AdminRole_ADMIN_ROLE_OWNER
	case roleAdmin:
		return pb.AdminRole_ADMIN_ROLE_ADMIN
	case roleAuditor:
		return pb.AdminRole_ADMIN_ROLE_AUDITOR
	default:
		return pb.AdminRole_ADMIN_ROLE_UNSPECIFIED
	}
}

func storeRole(role pb.AdminRole) (string, error) {
	switch role {
	case pb.AdminRole_ADMIN_ROLE_OWNER:
		return roleOwner, nil
	case pb.AdminRole_ADMIN_ROLE_ADMIN:
		return roleAdmin, nil
	case pb.AdminRole_ADMIN_ROLE_AUDITOR:
		return roleAuditor, nil
	default:
		return "", fmt.Errorf("invalid admin role")
	}
}

func timestamppbOrNil(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if !ts.Valid {
		return nil
	}
	return timestamppb.New(ts.Time)
}

func (s *Service) claimsFromContext(ctx context.Context) (*auth.AdminClaims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authorization metadata required")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization metadata required")
	}
	return s.parseAuthorization(values[0])
}

func (s *Service) parseAuthorization(header string) (*auth.AdminClaims, error) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, status.Error(codes.Unauthenticated, "bearer token required")
	}
	claims, err := s.tokens.ParseAdminToken(parts[1])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid admin token")
	}
	return claims, nil
}

func hasRole(role string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(role, candidate) {
			return true
		}
	}
	return false
}

func uuidFromPG(value pgtype.UUID) (uuid.UUID, error) {
	if !value.Valid {
		return uuid.UUID{}, fmt.Errorf("uuid invalid")
	}
	return uuid.FromBytes(value.Bytes[:])
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	var bytes [16]byte
	copy(bytes[:], id[:])
	return pgtype.UUID{Bytes: bytes, Valid: true}
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
