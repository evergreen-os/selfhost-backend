package policies

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/audit"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"github.com/evergreenos/selfhost-backend/internal/config"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakePolicyStore struct {
	policies map[string]generated.Policy
}

func newFakePolicyStore() *fakePolicyStore {
	return &fakePolicyStore{policies: make(map[string]generated.Policy)}
}

func (f *fakePolicyStore) CreatePolicy(ctx context.Context, arg generated.CreatePolicyParams) (generated.Policy, error) {
	record := generated.Policy{
		PolicyID:         arg.PolicyID,
		TenantID:         arg.TenantID,
		Name:             arg.Name,
		VersionTimestamp: arg.VersionTimestamp,
		PolicyBundle:     append([]byte(nil), arg.PolicyBundle...),
		Signature:        arg.Signature,
		SigningKeyID:     arg.SigningKeyID,
	}
	f.policies[arg.PolicyID] = record
	return record, nil
}

func (f *fakePolicyStore) GetPolicyByID(ctx context.Context, policyID string) (generated.Policy, error) {
	record, ok := f.policies[policyID]
	if !ok {
		return generated.Policy{}, status.Error(codes.NotFound, "policy not found")
	}
	return record, nil
}

func (f *fakePolicyStore) GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (generated.Policy, error) {
	var latest generated.Policy
	found := false
	for _, record := range f.policies {
		if !record.TenantID.Valid || record.TenantID != tenantID {
			continue
		}
		if !found || record.VersionTimestamp.Time.After(latest.VersionTimestamp.Time) {
			latest = record
			found = true
		}
	}
	if !found {
		return generated.Policy{}, status.Error(codes.NotFound, "not found")
	}
	return latest, nil
}

func (f *fakePolicyStore) ListPoliciesByTenant(ctx context.Context, arg generated.ListPoliciesByTenantParams) ([]generated.Policy, error) {
	results := make([]generated.Policy, 0)
	for _, record := range f.policies {
		if record.TenantID == arg.TenantID {
			results = append(results, record)
		}
	}
	// simple deterministic ordering by timestamp desc
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].VersionTimestamp.Time.After(results[i].VersionTimestamp.Time) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	start := int(arg.Offset)
	if start > len(results) {
		return []generated.Policy{}, nil
	}
	end := start + int(arg.Limit)
	if arg.Limit <= 0 || end > len(results) {
		end = len(results)
	}
	return results[start:end], nil
}

func (f *fakePolicyStore) UpdatePolicy(ctx context.Context, arg generated.UpdatePolicyParams) (generated.Policy, error) {
	record, ok := f.policies[arg.PolicyID]
	if !ok {
		return generated.Policy{}, status.Error(codes.NotFound, "policy not found")
	}
	record.Name = arg.Name
	record.VersionTimestamp = arg.VersionTimestamp
	record.PolicyBundle = append([]byte(nil), arg.PolicyBundle...)
	record.Signature = arg.Signature
	record.SigningKeyID = arg.SigningKeyID
	f.policies[arg.PolicyID] = record
	return record, nil
}

func (f *fakePolicyStore) DeletePolicy(ctx context.Context, policyID string) error {
	delete(f.policies, policyID)
	return nil
}

type fakePolicyAuditor struct {
	entries []audit.Entry
}

func (f *fakePolicyAuditor) Record(ctx context.Context, entry audit.Entry) error {
	f.entries = append(f.entries, entry)
	return nil
}

func TestAdminServiceCreatePolicy(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	policySvc, err := NewPolicyService(store, configForTests())
	if err != nil {
		t.Fatalf("new policy service: %v", err)
	}
	policySvc.WithClock(func() time.Time { return time.Unix(1730000000, 0).UTC() })
	auditor := &fakePolicyAuditor{}
	mgr := mustTokenManager(t)
	svc := NewAdminService(policySvc, mgr, auditor)

	tenantID := uuid.New()
	actor := &auth.AdminClaims{Subject: uuid.New().String(), TenantID: tenantID.String(), Role: roleOwner}
	req := &pb.CreatePolicyRequest{
		TenantId: tenantID.String(),
		Name:     "Baseline",
		Policy: &pb.PolicyBundle{
			Name:     "Baseline",
			Version:  timestamppb.Now(),
			Apps:     &pb.AppPolicy{AutoInstallRequired: true},
			Security: &pb.SecurityPolicy{RequireScreenLock: true},
		},
	}
	resp, err := svc.CreatePolicyWithClaims(ctx, actor, req)
	if err != nil {
		t.Fatalf("CreatePolicyWithClaims: %v", err)
	}
	if resp.Policy == nil {
		t.Fatalf("expected policy in response")
	}
	if resp.Policy.Signature == "" {
		t.Fatalf("expected signature to be populated")
	}
	if len(store.policies) != 1 {
		t.Fatalf("expected store to contain policy, got %d", len(store.policies))
	}
	if len(auditor.entries) != 1 {
		t.Fatalf("expected audit entry")
	}
}

func TestAdminServiceListPoliciesPagination(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	policySvc, err := NewPolicyService(store, configForTests())
	if err != nil {
		t.Fatalf("policy service: %v", err)
	}
	baseTime := time.Unix(1730001000, 0).UTC()
	policySvc.WithClock(func() time.Time {
		base := baseTime
		baseTime = baseTime.Add(time.Minute)
		return base
	})
	mgr := mustTokenManager(t)
	svc := NewAdminService(policySvc, mgr, nil)
	tenantID := uuid.New()
	actor := &auth.AdminClaims{Subject: uuid.New().String(), TenantID: tenantID.String(), Role: roleOwner}
	for i := 0; i < 3; i++ {
		bundle := &pb.PolicyBundle{Apps: &pb.AppPolicy{AutoInstallRequired: true}, Security: &pb.SecurityPolicy{RequireScreenLock: true}}
		if _, err := svc.CreatePolicyWithClaims(ctx, actor, &pb.CreatePolicyRequest{TenantId: tenantID.String(), Name: fmt.Sprintf("p-%d", i), Policy: bundle}); err != nil {
			t.Fatalf("create policy %d: %v", i, err)
		}
	}
	listResp, err := svc.ListPoliciesWithClaims(ctx, actor, &pb.ListPoliciesRequest{TenantId: tenantID.String(), PageSize: 2})
	if err != nil {
		t.Fatalf("ListPoliciesWithClaims: %v", err)
	}
	if len(listResp.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(listResp.Policies))
	}
	if listResp.NextPageToken == "" {
		t.Fatalf("expected next page token")
	}
	nextResp, err := svc.ListPoliciesWithClaims(ctx, actor, &pb.ListPoliciesRequest{TenantId: tenantID.String(), PageToken: listResp.NextPageToken})
	if err != nil {
		t.Fatalf("ListPoliciesWithClaims next: %v", err)
	}
	if len(nextResp.Policies) != 1 {
		t.Fatalf("expected final page to contain 1 policy, got %d", len(nextResp.Policies))
	}
}

func TestAdminServiceDeletePolicyRequiresRole(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	policySvc, err := NewPolicyService(store, configForTests())
	if err != nil {
		t.Fatalf("policy service: %v", err)
	}
	policySvc.WithClock(func() time.Time { return time.Unix(1730002000, 0).UTC() })
	svc := NewAdminService(policySvc, mustTokenManager(t), nil)
	tenantID := uuid.New()
	owner := &auth.AdminClaims{Subject: uuid.New().String(), TenantID: tenantID.String(), Role: roleOwner}
	bundle := &pb.PolicyBundle{Apps: &pb.AppPolicy{}, Security: &pb.SecurityPolicy{}}
	created, err := svc.CreatePolicyWithClaims(ctx, owner, &pb.CreatePolicyRequest{TenantId: tenantID.String(), Name: "keep", Policy: bundle})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	auditor := &auth.AdminClaims{Subject: uuid.New().String(), TenantID: tenantID.String(), Role: roleAuditor}
	if _, err := svc.DeletePolicyWithClaims(ctx, auditor, &pb.DeletePolicyRequest{PolicyId: created.Policy.Id}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestAdminServiceCreatePolicyRequiresMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	store := newFakePolicyStore()
	policySvc, err := NewPolicyService(store, configForTests())
	if err != nil {
		t.Fatalf("policy service: %v", err)
	}
	svc := NewAdminService(policySvc, mustTokenManager(t), nil)
	if _, err := svc.CreatePolicy(ctx, &pb.CreatePolicyRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func configForTests() config.PolicyConfig {
	return config.PolicyConfig{}
}

func mustTokenManager(t *testing.T) *auth.Manager {
	t.Helper()
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	return mgr
}
