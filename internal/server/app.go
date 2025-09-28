package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/admin"
	"github.com/evergreenos/selfhost-backend/internal/api"
	"github.com/evergreenos/selfhost-backend/internal/attestation"
	"github.com/evergreenos/selfhost-backend/internal/audit"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"github.com/evergreenos/selfhost-backend/internal/config"
	"github.com/evergreenos/selfhost-backend/internal/db"
	"github.com/evergreenos/selfhost-backend/internal/devices"
	"github.com/evergreenos/selfhost-backend/internal/events"
	"github.com/evergreenos/selfhost-backend/internal/policies"
	"github.com/evergreenos/selfhost-backend/internal/tenants"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DB is the subset of database behaviour required by the application lifecycle.
type DB interface {
	Close()
}

// DBFactory constructs a database connection from a DSN.
type DBFactory func(ctx context.Context, dsn string) (DB, error)

// Option configures the application server.
type Option func(*App)

// App wires together the EvergreenOS backend listeners and shared dependencies.
type App struct {
	cfg                *config.Config
	logger             *slog.Logger
	dbFactory          DBFactory
	grpcServer         *grpc.Server
	restHandler        http.Handler
	metricsHandler     http.Handler
	tokenFactory       func(*config.Config) (*auth.Manager, error)
	deviceFactory      func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (deviceService, error)
	adminFactory       func(*config.Config, DB, *auth.Manager) (adminService, error)
	policyFactory      func(*config.Config, DB) (*policies.PolicyService, error)
	policyAdminFactory func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (policyService, error)
	tenantFactory      func(*config.Config, DB, *auth.Manager) (tenantService, error)

	mu              sync.RWMutex
	started         bool
	database        DB
	grpcListener    net.Listener
	restListener    net.Listener
	metricsListener net.Listener
	restServer      *http.Server
	metricsServer   *http.Server
}

type deviceService interface {
	pb.DeviceServiceServer
	api.DeviceAPI
}

type adminService interface {
	pb.AdminServiceServer
	api.AdminAPI
}

type policyService interface {
	pb.PolicyServiceServer
	api.PolicyAPI
}

type tenantService interface {
	pb.TenantServiceServer
	api.TenantAPI
}

func (a *App) ensureGRPCServer() (*grpc.Server, error) {
	a.mu.RLock()
	if a.grpcServer != nil {
		srv := a.grpcServer
		a.mu.RUnlock()
		return srv, nil
	}
	a.mu.RUnlock()

	var opts []api.GRPCOption
	if a.cfg.Server.TLSCertFile != "" && a.cfg.Server.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(a.cfg.Server.TLSCertFile, a.cfg.Server.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS credentials: %w", err)
		}
		opts = append(opts, api.WithServerOptions(grpc.Creds(creds)))
	}

	srv := api.NewGRPCServer(opts...)
	a.mu.Lock()
	a.grpcServer = srv
	a.mu.Unlock()
	return srv, nil
}

// WithDBFactory overrides the database factory used during Start.
func WithDBFactory(factory DBFactory) Option {
	return func(a *App) {
		if factory != nil {
			a.dbFactory = factory
		}
	}
}

// WithLogger overrides the slog logger used for lifecycle events.
func WithLogger(logger *slog.Logger) Option {
	return func(a *App) {
		if logger != nil {
			a.logger = logger
		}
	}
}

// WithRESTHandler overrides the REST handler mounted on the HTTP server.
func WithRESTHandler(handler http.Handler) Option {
	return func(a *App) {
		if handler != nil {
			a.restHandler = handler
		}
	}
}

// WithGRPCServer overrides the gRPC server instance used by the app.
func WithGRPCServer(server *grpc.Server) Option {
	return func(a *App) {
		if server != nil {
			a.grpcServer = server
		}
	}
}

// WithMetricsHandler overrides the Prometheus metrics handler.
func WithMetricsHandler(handler http.Handler) Option {
	return func(a *App) {
		if handler != nil {
			a.metricsHandler = handler
		}
	}
}

// WithTokenManagerFactory overrides the auth manager factory used during startup.
func WithTokenManagerFactory(factory func(*config.Config) (*auth.Manager, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.tokenFactory = factory
		}
	}
}

// WithDeviceServiceFactory overrides the device service factory used to expose APIs.
func WithDeviceServiceFactory(factory func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (deviceService, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.deviceFactory = factory
		}
	}
}

// WithAdminServiceFactory overrides the admin service factory used to expose APIs.
func WithAdminServiceFactory(factory func(*config.Config, DB, *auth.Manager) (adminService, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.adminFactory = factory
		}
	}
}

// WithPolicyFactory overrides the shared policy manager factory.
func WithPolicyFactory(factory func(*config.Config, DB) (*policies.PolicyService, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.policyFactory = factory
		}
	}
}

// WithPolicyAdminServiceFactory overrides the policy admin service factory.
func WithPolicyAdminServiceFactory(factory func(*config.Config, DB, *auth.Manager, *policies.PolicyService) (policyService, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.policyAdminFactory = factory
		}
	}
}

// WithTenantServiceFactory overrides the tenant service factory.
func WithTenantServiceFactory(factory func(*config.Config, DB, *auth.Manager) (tenantService, error)) Option {
	return func(a *App) {
		if factory != nil {
			a.tenantFactory = factory
		}
	}
}

// NewApp assembles an EvergreenOS application using the provided configuration.
func NewApp(cfg *config.Config, opts ...Option) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}

	app := &App{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
		dbFactory: func(ctx context.Context, dsn string) (DB, error) {
			return db.New(ctx, dsn)
		},
		restHandler:        nil,
		metricsHandler:     promhttp.Handler(),
		tokenFactory:       defaultTokenFactory,
		deviceFactory:      defaultDeviceFactory,
		adminFactory:       defaultAdminFactory,
		policyFactory:      defaultPolicyFactory,
		policyAdminFactory: defaultPolicyAdminFactory,
		tenantFactory:      defaultTenantFactory,
	}

	for _, opt := range opts {
		opt(app)
	}

	return app, nil
}

// Start initializes dependencies and begins serving all listeners.
func (a *App) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	a.mu.Unlock()

	grpcServer, err := a.ensureGRPCServer()
	if err != nil {
		return fmt.Errorf("configure gRPC server: %w", err)
	}

	database, err := a.dbFactory(ctx, a.cfg.Database.DSN())
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}

	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", a.cfg.Server.GRPCPort))
	if err != nil {
		database.Close()
		return fmt.Errorf("listen gRPC: %w", err)
	}

	restListener, err := net.Listen("tcp", fmt.Sprintf(":%d", a.cfg.Server.RESTPort))
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		return fmt.Errorf("listen REST: %w", err)
	}

	var metricsListener net.Listener
	if a.cfg.Metrics.Enabled {
		metricsListener, err = net.Listen("tcp", fmt.Sprintf(":%d", a.cfg.Metrics.Port))
		if err != nil {
			database.Close()
			_ = grpcListener.Close()
			_ = restListener.Close()
			return fmt.Errorf("listen metrics: %w", err)
		}
	}

	tokenManager, err := a.tokenFactory(a.cfg)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init auth manager: %w", err)
	}

	policyManager, err := a.policyFactory(a.cfg, database)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init policy manager: %w", err)
	}

	deviceService, err := a.deviceFactory(a.cfg, database, tokenManager, policyManager)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init device service: %w", err)
	}

	adminService, err := a.adminFactory(a.cfg, database, tokenManager)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init admin service: %w", err)
	}

	policyService, err := a.policyAdminFactory(a.cfg, database, tokenManager, policyManager)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init policy service: %w", err)
	}

	tenantService, err := a.tenantFactory(a.cfg, database, tokenManager)
	if err != nil {
		database.Close()
		_ = grpcListener.Close()
		_ = restListener.Close()
		if metricsListener != nil {
			_ = metricsListener.Close()
		}
		return fmt.Errorf("init tenant service: %w", err)
	}

	pb.RegisterDeviceServiceServer(grpcServer, deviceService)
	pb.RegisterAdminServiceServer(grpcServer, adminService)
	pb.RegisterPolicyServiceServer(grpcServer, policyService)
	pb.RegisterTenantServiceServer(grpcServer, tenantService)

	if a.restHandler == nil {
		a.restHandler = api.NewRouter(api.RouterConfig{Device: deviceService, Admin: adminService, Policy: policyService, Tenant: tenantService, TokenManager: tokenManager})
	}

	restServer := &http.Server{Handler: a.restHandler}
	var metricsServer *http.Server
	if a.cfg.Metrics.Enabled {
		metricsServer = &http.Server{Handler: a.metricsHandler}
	}

	a.mu.Lock()
	a.database = database
	a.grpcListener = grpcListener
	a.restListener = restListener
	a.metricsListener = metricsListener
	a.restServer = restServer
	a.metricsServer = metricsServer
	a.grpcServer = grpcServer
	a.started = true
	a.mu.Unlock()

	go func() {
		if err := a.serveGRPC(grpcServer, grpcListener); err != nil {
			a.logger.Error("gRPC server exited", slog.String("error", err.Error()))
		}
	}()

	go func() {
		if err := a.serveREST(restServer, restListener); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				a.logger.Error("REST server exited", slog.String("error", err.Error()))
			}
		}
	}()

	if metricsServer != nil && metricsListener != nil {
		go func() {
			if err := a.serveMetrics(metricsServer, metricsListener); err != nil {
				if !errors.Is(err, http.ErrServerClosed) {
					a.logger.Error("metrics server exited", slog.String("error", err.Error()))
				}
			}
		}()
	}

	return nil
}

func (a *App) serveGRPC(server *grpc.Server, lis net.Listener) error {
	return server.Serve(lis)
}

func (a *App) serveREST(server *http.Server, lis net.Listener) error {
	if a.cfg.Server.TLSCertFile != "" && a.cfg.Server.TLSKeyFile != "" {
		return server.ServeTLS(lis, a.cfg.Server.TLSCertFile, a.cfg.Server.TLSKeyFile)
	}
	return server.Serve(lis)
}

func (a *App) serveMetrics(server *http.Server, lis net.Listener) error {
	return server.Serve(lis)
}

// Shutdown gracefully stops all listeners and closes shared dependencies.
func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	if !a.started {
		a.mu.Unlock()
		return nil
	}

	database := a.database
	grpcServer := a.grpcServer
	restServer := a.restServer
	metricsServer := a.metricsServer
	a.database = nil
	a.grpcServer = nil
	a.grpcListener = nil
	a.restListener = nil
	a.metricsListener = nil
	a.restServer = nil
	a.metricsServer = nil
	a.started = false
	a.mu.Unlock()

	var errs []error

	if restServer != nil {
		if err := restServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("shutdown REST: %w", err))
		}
	}

	if metricsServer != nil {
		if err := metricsServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("shutdown metrics: %w", err))
		}
	}

	if grpcServer != nil {
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			grpcServer.Stop()
			<-done
		}
	}

	if database != nil {
		database.Close()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// GRPCAddr returns the bound address of the gRPC listener.
func (a *App) GRPCAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.grpcListener == nil {
		return ""
	}
	return a.grpcListener.Addr().String()
}

// RESTAddr returns the bound address of the REST listener.
func (a *App) RESTAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.restListener == nil {
		return ""
	}
	return a.restListener.Addr().String()
}

// MetricsAddr returns the bound address of the metrics listener, if enabled.
func (a *App) MetricsAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.metricsListener == nil {
		return ""
	}
	return a.metricsListener.Addr().String()
}

func defaultTokenFactory(cfg *config.Config) (*auth.Manager, error) {
	if cfg.Auth.JWTSecret == "" {
		return nil, fmt.Errorf("auth.jwt_secret is required")
	}
	adminHours := cfg.Auth.JWTExpiryHours
	if adminHours <= 0 {
		adminHours = 1
	}
	deviceHours := cfg.Auth.DeviceTokenExpiryHrs
	if deviceHours <= 0 {
		deviceHours = 24
	}
	return auth.NewManager([]byte(cfg.Auth.JWTSecret), time.Duration(adminHours)*time.Hour, time.Duration(deviceHours)*time.Hour)
}

func defaultDeviceFactory(cfg *config.Config, database DB, manager *auth.Manager, policySvc *policies.PolicyService) (deviceService, error) {
	realDB, ok := database.(*db.DB)
	if !ok {
		return nil, fmt.Errorf("device service requires *db.DB instance")
	}
	if policySvc == nil {
		return nil, fmt.Errorf("policy manager is required")
	}
	eventsSvc, err := events.NewService(realDB.Queries(), 0)
	if err != nil {
		return nil, fmt.Errorf("init events service: %w", err)
	}
	var attestor devices.QuoteVerifier
	if cfg.Attestation.Enabled {
		ttl := time.Duration(cfg.Attestation.QuoteTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		verifier, err := attestation.NewVerifier(ttl)
		if err != nil {
			return nil, fmt.Errorf("init attestation verifier: %w", err)
		}
		attestor = verifier
	}
	svc := devices.NewDeviceServiceWithDependencies(realDB.Queries(), policySvc, manager, eventsSvc, attestor)
	return svc, nil
}

func defaultAdminFactory(cfg *config.Config, database DB, manager *auth.Manager) (adminService, error) {
	realDB, ok := database.(*db.DB)
	if !ok {
		return nil, fmt.Errorf("admin service requires *db.DB instance")
	}
	recorder, err := audit.NewRecorder(realDB.Pool())
	if err != nil {
		return nil, fmt.Errorf("init audit recorder: %w", err)
	}
	svc := admin.NewService(realDB.Queries(), manager, recorder)
	return svc, nil
}

func defaultPolicyFactory(cfg *config.Config, database DB) (*policies.PolicyService, error) {
	realDB, ok := database.(*db.DB)
	if !ok {
		return nil, fmt.Errorf("policy manager requires *db.DB instance")
	}
	svc, err := policies.NewPolicyService(realDB.Queries(), cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("init policy manager: %w", err)
	}
	return svc, nil
}

func defaultPolicyAdminFactory(cfg *config.Config, database DB, manager *auth.Manager, policySvc *policies.PolicyService) (policyService, error) {
	realDB, ok := database.(*db.DB)
	if !ok {
		return nil, fmt.Errorf("policy admin service requires *db.DB instance")
	}
	if policySvc == nil {
		return nil, fmt.Errorf("policy manager is required")
	}
	recorder, err := audit.NewRecorder(realDB.Pool())
	if err != nil {
		return nil, fmt.Errorf("init audit recorder: %w", err)
	}
	svc := policies.NewAdminService(policySvc, manager, recorder)
	return svc, nil
}

func defaultTenantFactory(cfg *config.Config, database DB, manager *auth.Manager) (tenantService, error) {
	realDB, ok := database.(*db.DB)
	if !ok {
		return nil, fmt.Errorf("tenant service requires *db.DB instance")
	}
	recorder, err := audit.NewRecorder(realDB.Pool())
	if err != nil {
		return nil, fmt.Errorf("init audit recorder: %w", err)
	}
	svc := tenants.NewService(realDB.Queries(), manager, recorder)
	return svc, nil
}
