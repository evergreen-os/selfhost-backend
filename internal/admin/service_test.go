package admin

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/audit"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

type mockStore struct {
	userByUsername generated.User
	listUsers      []generated.User
	createdUser    generated.User
	tenant         generated.Tenant

	createErr error
	loginErr  error
	listErr   error
	tenantErr error

	createParams generated.CreateUserParams
	listParams   generated.ListUsersByTenantParams
	updatedLogin bool
}

func (m *mockStore) GetUserByUsername(ctx context.Context, username string) (generated.User, error) {
	if m.loginErr != nil {
		return generated.User{}, m.loginErr
	}
	if username != m.userByUsername.Username {
		return generated.User{}, errors.New("not found")
	}
	return m.userByUsername, nil
}

func (m *mockStore) UpdateUserLastLogin(ctx context.Context, id pgtype.UUID) (generated.User, error) {
	m.updatedLogin = true
	m.userByUsername.LastLoginAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	return m.userByUsername, nil
}

func (m *mockStore) CreateUser(ctx context.Context, params generated.CreateUserParams) (generated.User, error) {
	if m.createErr != nil {
		return generated.User{}, m.createErr
	}
	m.createParams = params
	m.createdUser = generated.User{
		ID:           uuidToPG(uuid.New()),
		TenantID:     params.TenantID,
		Username:     params.Username,
		Email:        params.Email,
		PasswordHash: params.PasswordHash,
		Role:         params.Role,
		CreatedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	return m.createdUser, nil
}

func (m *mockStore) ListUsersByTenant(ctx context.Context, params generated.ListUsersByTenantParams) ([]generated.User, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	m.listParams = params
	start := int(params.Offset)
	if start > len(m.listUsers) {
		return []generated.User{}, nil
	}
	end := start + int(params.Limit)
	if params.Limit <= 0 || end > len(m.listUsers) {
		end = len(m.listUsers)
	}
	return m.listUsers[start:end], nil
}

func (m *mockStore) GetTenantByID(ctx context.Context, id pgtype.UUID) (generated.Tenant, error) {
	if m.tenantErr != nil {
		return generated.Tenant{}, m.tenantErr
	}
	if !idsEqual(id, m.tenant.ID) {
		return generated.Tenant{}, errors.New("tenant not found")
	}
	return m.tenant, nil
}

type mockAuditor struct {
	entries []audit.Entry
	err     error
}

func (m *mockAuditor) Record(ctx context.Context, entry audit.Entry) error {
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, entry)
	return nil
}

func TestService_LoginSuccess(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{}
	auditor := &mockAuditor{}

	tenantID := uuid.New()
	userID := uuid.New()
	hashed, err := bcrypt.GenerateFromPassword([]byte("StrongPass!1"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	store.userByUsername = generated.User{
		ID:           uuidToPG(userID),
		TenantID:     uuidToPG(tenantID),
		Username:     "owner",
		Email:        "owner@example.com",
		PasswordHash: string(hashed),
		Role:         "owner",
		CreatedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}

	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	svc := NewService(store, mgr, auditor)
	svc.now = func() time.Time { return time.Unix(1730000000, 0).UTC() }

	resp, err := svc.Login(ctx, &pb.AdminLoginRequest{Username: "owner", Password: "StrongPass!1"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected token")
	}
	if resp.User.Username != "owner" {
		t.Fatalf("unexpected username: %s", resp.User.Username)
	}
	if resp.User.Role != pb.AdminRole_ADMIN_ROLE_OWNER {
		t.Fatalf("unexpected role: %v", resp.User.Role)
	}
	if !store.updatedLogin {
		t.Fatalf("expected last login update")
	}
	if len(auditor.entries) != 1 {
		t.Fatalf("expected audit entry, got %d", len(auditor.entries))
	}
	if auditor.entries[0].Action != "admin.login" {
		t.Fatalf("unexpected audit action: %s", auditor.entries[0].Action)
	}
}

func TestService_CreateUser(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	store := &mockStore{
		tenant: generated.Tenant{ID: uuidToPG(tenantID)},
	}
	auditor := &mockAuditor{}

	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	svc := NewService(store, mgr, auditor)

	actor := &auth.AdminClaims{Subject: uuid.NewString(), TenantID: tenantID.String(), Role: "owner"}
	req := &pb.CreateAdminUserRequest{
		TenantId: tenantID.String(),
		Username: "new-admin",
		Email:    "new@example.com",
		Password: "Sup3rStrong!",
		Role:     pb.AdminRole_ADMIN_ROLE_ADMIN,
	}

	resp, err := svc.CreateUserWithClaims(ctx, actor, req)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if resp.User == nil {
		t.Fatalf("expected user in response")
	}
	if resp.User.Username != "new-admin" {
		t.Fatalf("unexpected username: %s", resp.User.Username)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(store.createParams.PasswordHash), []byte("Sup3rStrong!")); err != nil {
		t.Fatalf("password not hashed: %v", err)
	}
	if len(auditor.entries) != 1 {
		t.Fatalf("expected audit entry, got %d", len(auditor.entries))
	}
	if auditor.entries[0].Action != "admin.user.create" {
		t.Fatalf("unexpected action: %s", auditor.entries[0].Action)
	}
}

func TestService_ListUsers(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	store := &mockStore{
		listUsers: []generated.User{
			{
				ID:        uuidToPG(uuid.New()),
				TenantID:  uuidToPG(tenantID),
				Username:  "owner",
				Email:     "owner@example.com",
				Role:      "owner",
				CreatedAt: pgtype.Timestamptz{Time: time.Unix(10, 0), Valid: true},
				UpdatedAt: pgtype.Timestamptz{Time: time.Unix(10, 0), Valid: true},
			},
			{
				ID:        uuidToPG(uuid.New()),
				TenantID:  uuidToPG(tenantID),
				Username:  "auditor",
				Email:     "auditor@example.com",
				Role:      "auditor",
				CreatedAt: pgtype.Timestamptz{Time: time.Unix(11, 0), Valid: true},
				UpdatedAt: pgtype.Timestamptz{Time: time.Unix(11, 0), Valid: true},
			},
		},
	}
	auditor := &mockAuditor{}

	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	svc := NewService(store, mgr, auditor)

	actor := &auth.AdminClaims{Subject: uuid.NewString(), TenantID: tenantID.String(), Role: "admin"}
	resp, err := svc.ListUsersWithClaims(ctx, actor, &pb.ListAdminUsersRequest{PageSize: 1})
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("expected single user page")
	}
	if resp.Users[0].Username != "owner" {
		t.Fatalf("unexpected first username: %s", resp.Users[0].Username)
	}
	if resp.NextPageToken == "" {
		t.Fatalf("expected next page token")
	}
	offset, err := strconv.Atoi(resp.NextPageToken)
	if err != nil || offset != 1 {
		t.Fatalf("unexpected next token: %s", resp.NextPageToken)
	}
}

func idsEqual(a, b pgtype.UUID) bool {
	return a.Valid == b.Valid && a.Bytes == b.Bytes
}
