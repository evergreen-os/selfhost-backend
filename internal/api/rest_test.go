package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeDeviceAPI struct {
	enrollReq *pb.EnrollDeviceRequest
	stateReq  *pb.ReportStateRequest
	eventsReq *pb.ReportEventsRequest
	policyReq *pb.PullPolicyRequest
	attestReq *pb.AttestBootRequest
}

func (f *fakeDeviceAPI) EnrollDevice(_ context.Context, req *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	f.enrollReq = req
	return &pb.EnrollDeviceResponse{DeviceId: "device-123"}, nil
}

func (f *fakeDeviceAPI) PullPolicy(_ context.Context, req *pb.PullPolicyRequest) (*pb.PullPolicyResponse, error) {
	f.policyReq = req
	return &pb.PullPolicyResponse{}, nil
}

func (f *fakeDeviceAPI) ReportState(_ context.Context, req *pb.ReportStateRequest) (*pb.ReportStateResponse, error) {
	f.stateReq = req
	return &pb.ReportStateResponse{}, nil
}

func (f *fakeDeviceAPI) ReportEvents(_ context.Context, req *pb.ReportEventsRequest) (*pb.ReportEventsResponse, error) {
	f.eventsReq = req
	return &pb.ReportEventsResponse{}, nil
}

func (f *fakeDeviceAPI) AttestBoot(_ context.Context, req *pb.AttestBootRequest) (*pb.AttestBootResponse, error) {
	f.attestReq = req
	return &pb.AttestBootResponse{Verified: true}, nil
}

type fakeAdminAPI struct {
	loginReq     *pb.AdminLoginRequest
	createReq    *pb.CreateAdminUserRequest
	createClaims *auth.AdminClaims
	listReq      *pb.ListAdminUsersRequest
	listClaims   *auth.AdminClaims
}

func (f *fakeAdminAPI) Login(_ context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	f.loginReq = req
	return &pb.AdminLoginResponse{AccessToken: "token", ExpiresAt: timestamppb.Now()}, nil
}

func (f *fakeAdminAPI) CreateUserWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error) {
	f.createClaims = claims
	f.createReq = req
	return &pb.CreateAdminUserResponse{User: &pb.AdminUser{Username: req.Username}}, nil
}

func (f *fakeAdminAPI) ListUsersWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error) {
	f.listClaims = claims
	f.listReq = req
	return &pb.ListAdminUsersResponse{Users: []*pb.AdminUser{{Username: "owner"}}}, nil
}

type fakePolicyAPI struct {
	createClaims *auth.AdminClaims
	updateClaims *auth.AdminClaims
	deleteClaims *auth.AdminClaims
	getClaims    *auth.AdminClaims
	listClaims   *auth.AdminClaims

	createReq *pb.CreatePolicyRequest
	updateReq *pb.UpdatePolicyRequest
	deleteReq *pb.DeletePolicyRequest
	getReq    *pb.GetPolicyRequest
	listReq   *pb.ListPoliciesRequest
}

func (f *fakePolicyAPI) CreatePolicyWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error) {
	f.createClaims = claims
	f.createReq = req
	return &pb.CreatePolicyResponse{Policy: &pb.PolicyBundle{Id: "policy-created"}}, nil
}

func (f *fakePolicyAPI) UpdatePolicyWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	f.updateClaims = claims
	f.updateReq = req
	return &pb.UpdatePolicyResponse{Policy: &pb.PolicyBundle{Id: req.PolicyId}}, nil
}

func (f *fakePolicyAPI) DeletePolicyWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error) {
	f.deleteClaims = claims
	f.deleteReq = req
	return &pb.DeletePolicyResponse{}, nil
}

func (f *fakePolicyAPI) GetPolicyWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error) {
	f.getClaims = claims
	f.getReq = req
	return &pb.GetPolicyResponse{Policy: &pb.PolicyBundle{Id: req.PolicyId}}, nil
}

func (f *fakePolicyAPI) ListPoliciesWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	f.listClaims = claims
	f.listReq = req
	return &pb.ListPoliciesResponse{Policies: []*pb.PolicyBundle{{Id: "p-1"}}, NextPageToken: "nxt"}, nil
}

type fakeTenantAPI struct {
	createClaims *auth.AdminClaims
	listClaims   *auth.AdminClaims
	rotateClaims *auth.AdminClaims

	createReq *pb.CreateTenantRequest
	listReq   *pb.ListTenantsRequest
	rotateReq *pb.RotateTenantSecretRequest
}

func (f *fakeTenantAPI) CreateTenantWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	f.createClaims = claims
	f.createReq = req
	return &pb.CreateTenantResponse{Tenant: &pb.Tenant{Id: "tenant-created"}}, nil
}

func (f *fakeTenantAPI) ListTenantsWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	f.listClaims = claims
	f.listReq = req
	return &pb.ListTenantsResponse{Tenants: []*pb.Tenant{{Id: "tenant"}}, NextPageToken: "next"}, nil
}

func (f *fakeTenantAPI) RotateTenantSecretWithClaims(_ context.Context, claims *auth.AdminClaims, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error) {
	f.rotateClaims = claims
	f.rotateReq = req
	return &pb.RotateTenantSecretResponse{Tenant: &pb.Tenant{Id: req.TenantId}}, nil
}

func TestRouterExposesDeviceEndpoints(t *testing.T) {
	api := &fakeDeviceAPI{}
	router := NewRouter(RouterConfig{Device: api})

	enrollBody := body(t, &pb.EnrollDeviceRequest{EnrollmentToken: "tok"})
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/enroll", enrollBody)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if api.enrollReq == nil || api.enrollReq.EnrollmentToken != "tok" {
		t.Fatalf("expected enroll request to be forwarded")
	}

	stateBody := body(t, &pb.ReportStateRequest{DeviceToken: "token"})
	req = httptest.NewRequest(http.MethodPost, "/v1/devices/abc/state", stateBody)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if api.stateReq == nil || api.stateReq.DeviceId != "abc" {
		t.Fatalf("expected state device id to be set")
	}

	eventsBody := body(t, &pb.ReportEventsRequest{Events: []*pb.DeviceEvent{{EventId: "e1", Timestamp: timestamppb.Now(), Message: "test"}}})
	req = httptest.NewRequest(http.MethodPost, "/v1/devices/abc/events", eventsBody)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if api.eventsReq == nil || api.eventsReq.DeviceId != "abc" {
		t.Fatalf("expected events request device id to be set")
	}

	policyBody := body(t, &pb.PullPolicyRequest{DeviceToken: "tok"})
	req = httptest.NewRequest(http.MethodPost, "/v1/devices/abc/policy", policyBody)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if api.policyReq == nil || api.policyReq.DeviceId != "abc" {
		t.Fatalf("expected policy device id to be set")
	}

	attestBody := body(t, &pb.AttestBootRequest{DeviceToken: "tok", Nonce: "nonce", ExpectedNonce: "nonce", Quote: []byte("q"), Signature: []byte("s")})
	req = httptest.NewRequest(http.MethodPost, "/v1/devices/abc/attest", attestBody)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if api.attestReq == nil || api.attestReq.DeviceId != "abc" {
		t.Fatalf("expected attestation device id to be set")
	}
}

func TestRouterProvidesHealth(t *testing.T) {
	router := NewRouter(RouterConfig{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
}

func TestRouterAdminLogin(t *testing.T) {
	admin := &fakeAdminAPI{}
	router := NewRouter(RouterConfig{Admin: admin})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/login", body(t, &pb.AdminLoginRequest{Username: "owner", Password: "secret"}))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if admin.loginReq == nil || admin.loginReq.Username != "owner" {
		t.Fatalf("expected login request to reach admin API")
	}
}

func TestRouterAdminCreateUser(t *testing.T) {
	admin := &fakeAdminAPI{}
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	token, err := mgr.IssueAdminToken("actor", "tenant", "owner")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router := NewRouter(RouterConfig{Admin: admin, TokenManager: mgr})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users", body(t, &pb.CreateAdminUserRequest{Username: "new", Password: "pass"}))
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201 got %d", res.Code)
	}
	if admin.createClaims == nil || admin.createClaims.Subject != "actor" {
		t.Fatalf("expected actor claims to be forwarded")
	}
	if admin.createReq == nil || admin.createReq.Username != "new" {
		t.Fatalf("expected request payload forwarded")
	}
}

func TestRouterAdminListUsers(t *testing.T) {
	admin := &fakeAdminAPI{}
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	token, err := mgr.IssueAdminToken("actor", "tenant", "admin")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router := NewRouter(RouterConfig{Admin: admin, TokenManager: mgr})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users?page_size=2&page_token=4&tenant_id=tenant", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if admin.listClaims == nil || admin.listClaims.Subject != "actor" {
		t.Fatalf("expected claims on list request")
	}
	if admin.listReq == nil || admin.listReq.PageSize != 2 || admin.listReq.PageToken != "4" {
		t.Fatalf("expected query parameters forwarded")
	}
}

func TestRouterPolicyEndpoints(t *testing.T) {
	policy := &fakePolicyAPI{}
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	token, err := mgr.IssueAdminToken("actor", "tenant", "owner")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router := NewRouter(RouterConfig{Policy: policy, TokenManager: mgr})

	createBody := body(t, &pb.CreatePolicyRequest{Policy: &pb.PolicyBundle{Name: "baseline"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies", createBody)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201 got %d", res.Code)
	}
	if policy.createClaims == nil || policy.createClaims.Subject != "actor" {
		t.Fatalf("expected create claims to be forwarded")
	}
	if policy.createReq == nil || policy.createReq.Policy == nil {
		t.Fatalf("expected create request payload")
	}

	updateBody := body(t, &pb.UpdatePolicyRequest{Policy: &pb.PolicyBundle{Name: "updated"}})
	req = httptest.NewRequest(http.MethodPut, "/v1/admin/policies/p-123", updateBody)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if policy.updateReq == nil || policy.updateReq.PolicyId != "p-123" {
		t.Fatalf("expected policy id to be set on update")
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/admin/policies/p-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if policy.getReq == nil || policy.getReq.PolicyId != "p-123" {
		t.Fatalf("expected policy id on get")
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/admin/policies/p-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204 got %d", res.Code)
	}
	if policy.deleteReq == nil || policy.deleteReq.PolicyId != "p-123" {
		t.Fatalf("expected policy id on delete")
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/admin/policies?page_size=5&page_token=10&tenant_id=tenant", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if policy.listReq == nil || policy.listReq.PageSize != 5 || policy.listReq.PageToken != "10" {
		t.Fatalf("expected list request parameters to be forwarded")
	}
}

func TestRouterTenantEndpoints(t *testing.T) {
	tenantAPI := &fakeTenantAPI{}
	mgr, err := auth.NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	token, err := mgr.IssueAdminToken("actor", "tenant", "owner")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router := NewRouter(RouterConfig{Tenant: tenantAPI, TokenManager: mgr})

	createBody := body(t, &pb.CreateTenantRequest{TenantCode: "abc", Name: "school", EnrollmentSecret: "secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/tenants", createBody)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201 got %d", res.Code)
	}
	if tenantAPI.createReq == nil || tenantAPI.createReq.TenantCode != "abc" {
		t.Fatalf("expected tenant create payload forwarded")
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/admin/tenants?page_size=3&page_token=9", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if tenantAPI.listReq == nil || tenantAPI.listReq.PageSize != 3 || tenantAPI.listReq.PageToken != "9" {
		t.Fatalf("expected tenant list request parameters")
	}

	rotateBody := body(t, &pb.RotateTenantSecretRequest{EnrollmentSecret: "new-secret"})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/tenants/t-123/rotate-secret", rotateBody)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.Code)
	}
	if tenantAPI.rotateReq == nil || tenantAPI.rotateReq.TenantId != "t-123" {
		t.Fatalf("expected tenant id on rotate request")
	}
}

func body(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return bytes.NewBuffer(data)
}
