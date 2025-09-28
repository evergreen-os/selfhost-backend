package api

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type grpcOptions struct {
	unaryInterceptors  []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor
	serverOptions      []grpc.ServerOption
	registrations      []func(*grpc.Server)
}

// GRPCOption configures the gRPC server instance returned by NewGRPCServer.
type GRPCOption func(*grpcOptions)

// WithUnaryInterceptors appends unary interceptors to the server configuration.
func WithUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) GRPCOption {
	return func(o *grpcOptions) {
		o.unaryInterceptors = append(o.unaryInterceptors, interceptors...)
	}
}

// WithStreamInterceptors appends stream interceptors to the server configuration.
func WithStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) GRPCOption {
	return func(o *grpcOptions) {
		o.streamInterceptors = append(o.streamInterceptors, interceptors...)
	}
}

// WithServerOptions appends low-level server options before instantiation.
func WithServerOptions(opts ...grpc.ServerOption) GRPCOption {
	return func(o *grpcOptions) {
		o.serverOptions = append(o.serverOptions, opts...)
	}
}

// WithRegistrations registers additional services on the newly constructed server.
func WithRegistrations(fns ...func(*grpc.Server)) GRPCOption {
	return func(o *grpcOptions) {
		o.registrations = append(o.registrations, fns...)
	}
}

// NewGRPCServer constructs a gRPC server with health checking and reflection enabled.
func NewGRPCServer(opts ...GRPCOption) *grpc.Server {
	var cfg grpcOptions
	for _, opt := range opts {
		opt(&cfg)
	}

	if len(cfg.unaryInterceptors) > 0 {
		cfg.serverOptions = append(cfg.serverOptions, grpc.ChainUnaryInterceptor(cfg.unaryInterceptors...))
	}
	if len(cfg.streamInterceptors) > 0 {
		cfg.serverOptions = append(cfg.serverOptions, grpc.ChainStreamInterceptor(cfg.streamInterceptors...))
	}

	srv := grpc.NewServer(cfg.serverOptions...)
	for _, register := range cfg.registrations {
		register(srv)
	}

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, healthServer)
	reflection.Register(srv)

	return srv
}
