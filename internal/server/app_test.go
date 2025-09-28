package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/api"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"github.com/evergreenos/selfhost-backend/internal/config"
	"github.com/evergreenos/selfhost-backend/internal/policies"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type fakeDB struct {
	closed bool
}

func (f *fakeDB) Close() {
	f.closed = true
}

type fakeDeviceService struct {
	pb.UnimplementedDeviceServiceServer
}

func (f *fakeDeviceService) EnrollDevice(ctx context.Context, req *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	return &pb.EnrollDeviceResponse{}, nil
}

func (f *fakeDeviceService) PullPolicy(ctx context.Context, req *pb.PullPolicyRequest) (*pb.PullPolicyResponse, error) {
	return &pb.PullPolicyResponse{}, nil
}

func (f *fakeDeviceService) ReportState(ctx context.Context, req *pb.ReportStateRequest) (*pb.ReportStateResponse, error) {
	return &pb.ReportStateResponse{}, nil
}

func (f *fakeDeviceService) ReportEvents(ctx context.Context, req *pb.ReportEventsRequest) (*pb.ReportEventsResponse, error) {
	return &pb.ReportEventsResponse{}, nil
}

func (f *fakeDeviceService) AttestBoot(ctx context.Context, req *pb.AttestBootRequest) (*pb.AttestBootResponse, error) {
	return &pb.AttestBootResponse{}, nil
}

type fakeAdminService struct {
	pb.UnimplementedAdminServiceServer
}

func (f *fakeAdminService) CreateUser(ctx context.Context, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error) {
	return &pb.CreateAdminUserResponse{}, nil
}

func (f *fakeAdminService) Login(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	return &pb.AdminLoginResponse{}, nil
}

func (f *fakeAdminService) ListUsers(ctx context.Context, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error) {
	return &pb.ListAdminUsersResponse{}, nil
}

func (f *fakeAdminService) CreateUserWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error) {
	return &pb.CreateAdminUserResponse{}, nil
}

func (f *fakeAdminService) ListUsersWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error) {
	return &pb.ListAdminUsersResponse{}, nil
}

type fakePolicyAdminService struct {
	pb.UnimplementedPolicyServiceServer
}

func (f *fakePolicyAdminService) CreatePolicy(ctx context.Context, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error) {
	return &pb.CreatePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) UpdatePolicy(ctx context.Context, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	return &pb.UpdatePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) DeletePolicy(ctx context.Context, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error) {
	return &pb.DeletePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) GetPolicy(ctx context.Context, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error) {
	return &pb.GetPolicyResponse{}, nil
}

func (f *fakePolicyAdminService) ListPolicies(ctx context.Context, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	return &pb.ListPoliciesResponse{}, nil
}

func (f *fakePolicyAdminService) CreatePolicyWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error) {
	return &pb.CreatePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) UpdatePolicyWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	return &pb.UpdatePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) DeletePolicyWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error) {
	return &pb.DeletePolicyResponse{}, nil
}

func (f *fakePolicyAdminService) GetPolicyWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error) {
	return &pb.GetPolicyResponse{}, nil
}

func (f *fakePolicyAdminService) ListPoliciesWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	return &pb.ListPoliciesResponse{}, nil
}

type fakeTenantService struct {
	pb.UnimplementedTenantServiceServer
}

func (f *fakeTenantService) CreateTenant(ctx context.Context, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	return &pb.CreateTenantResponse{}, nil
}

func (f *fakeTenantService) ListTenants(ctx context.Context, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	return &pb.ListTenantsResponse{}, nil
}

func (f *fakeTenantService) RotateTenantSecret(ctx context.Context, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error) {
	return &pb.RotateTenantSecretResponse{}, nil
}

func (f *fakeTenantService) CreateTenantWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	return &pb.CreateTenantResponse{}, nil
}

func (f *fakeTenantService) ListTenantsWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	return &pb.ListTenantsResponse{}, nil
}

func (f *fakeTenantService) RotateTenantSecretWithClaims(ctx context.Context, claims *auth.AdminClaims, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error) {
	return &pb.RotateTenantSecretResponse{}, nil
}

func TestAppStartAndShutdown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPCPort = 0
	cfg.Server.RESTPort = 0
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 0
	cfg.Metrics.Path = "/metrics"
	cfg.Database.Host = "db"
	cfg.Database.Port = 5432
	cfg.Database.Name = "evergreen"
	cfg.Database.User = "svc"
	cfg.Auth.JWTSecret = strings.Repeat("a", 32)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := &fakeDB{}
	policyMgr, err := policies.NewPolicyService(nil, config.PolicyConfig{})
	if err != nil {
		t.Fatalf("policy manager: %v", err)
	}

	app, err := NewApp(cfg,
		WithDBFactory(func(ctx context.Context, dsn string) (DB, error) {
			if dsn == "" {
				t.Fatal("expected DSN to be set")
			}
			return db, nil
		}),
		WithGRPCServer(api.NewGRPCServer()),
		WithDeviceServiceFactory(func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (deviceService, error) {
			return &fakeDeviceService{}, nil
		}),
		WithAdminServiceFactory(func(*config.Config, DB, *auth.Manager) (adminService, error) {
			return &fakeAdminService{}, nil
		}),
		WithPolicyFactory(func(*config.Config, DB) (*policies.PolicyService, error) {
			return policyMgr, nil
		}),
		WithPolicyAdminServiceFactory(func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (policyService, error) {
			return &fakePolicyAdminService{}, nil
		}),
		WithTenantServiceFactory(func(*config.Config, DB, *auth.Manager) (tenantService, error) {
			return &fakeTenantService{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewApp error: %v", err)
	}

	if err := app.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	grpcTarget := hostPortFromAddr(app.GRPCAddr())
	restTarget := hostPortFromAddr(app.RESTAddr())
	metricsTarget := hostPortFromAddr(app.MetricsAddr())

	awaitHTTP(t, "http://"+restTarget+"/healthz")
	awaitHTTP(t, "http://"+metricsTarget+cfg.Metrics.Path)

	conn, err := grpc.DialContext(context.Background(), grpcTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial grpc: %v", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	if _, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health check: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := app.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !db.closed {
		t.Fatal("expected database to be closed")
	}
}

func TestAppStartFailsWhenDBFactoryFails(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPCPort = 0
	cfg.Server.RESTPort = 0

	app, err := NewApp(cfg, WithDBFactory(func(ctx context.Context, dsn string) (DB, error) {
		return nil, context.DeadlineExceeded
	}))
	if err != nil {
		t.Fatalf("NewApp error: %v", err)
	}

	if err := app.Start(context.Background()); err == nil {
		t.Fatal("expected start to fail")
	}
}

func TestAppDoesNotExposeMetricsWhenDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPCPort = 0
	cfg.Server.RESTPort = 0
	cfg.Metrics.Enabled = false
	cfg.Auth.JWTSecret = strings.Repeat("a", 32)

	policyMgr, err := policies.NewPolicyService(nil, config.PolicyConfig{})
	if err != nil {
		t.Fatalf("policy manager: %v", err)
	}

	app, err := NewApp(cfg,
		WithDBFactory(func(ctx context.Context, dsn string) (DB, error) {
			return &fakeDB{}, nil
		}),
		WithDeviceServiceFactory(func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (deviceService, error) {
			return &fakeDeviceService{}, nil
		}),
		WithAdminServiceFactory(func(*config.Config, DB, *auth.Manager) (adminService, error) {
			return &fakeAdminService{}, nil
		}),
		WithPolicyFactory(func(*config.Config, DB) (*policies.PolicyService, error) {
			return policyMgr, nil
		}),
		WithPolicyAdminServiceFactory(func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (policyService, error) {
			return &fakePolicyAdminService{}, nil
		}),
		WithTenantServiceFactory(func(*config.Config, DB, *auth.Manager) (tenantService, error) {
			return &fakeTenantService{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewApp error: %v", err)
	}

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if addr := app.MetricsAddr(); addr != "" {
		t.Fatalf("expected metrics addr to be empty, got %q", addr)
	}
	_ = app.Shutdown(context.Background())
}

func awaitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(url) // #nosec G107: test local connections only
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("endpoint %s not ready", url)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hostPortFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return "127.0.0.1:" + port
}
