package evergreenv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TenantServiceServer defines tenant management RPCs for Evergreen admins.
type TenantServiceServer interface {
	CreateTenant(context.Context, *CreateTenantRequest) (*CreateTenantResponse, error)
	ListTenants(context.Context, *ListTenantsRequest) (*ListTenantsResponse, error)
	RotateTenantSecret(context.Context, *RotateTenantSecretRequest) (*RotateTenantSecretResponse, error)
	mustEmbedUnimplementedTenantServiceServer()
}

// UnimplementedTenantServiceServer provides forward compatible stubs.
type UnimplementedTenantServiceServer struct{}

// CreateTenant implements the TenantServiceServer interface for forward compatibility.
func (UnimplementedTenantServiceServer) CreateTenant(context.Context, *CreateTenantRequest) (*CreateTenantResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateTenant not implemented")
}

// ListTenants implements the TenantServiceServer interface for forward compatibility.
func (UnimplementedTenantServiceServer) ListTenants(context.Context, *ListTenantsRequest) (*ListTenantsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListTenants not implemented")
}

// RotateTenantSecret implements the TenantServiceServer interface for forward compatibility.
func (UnimplementedTenantServiceServer) RotateTenantSecret(context.Context, *RotateTenantSecretRequest) (*RotateTenantSecretResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RotateTenantSecret not implemented")
}

// mustEmbedUnimplementedTenantServiceServer enforces forward compatibility.
func (UnimplementedTenantServiceServer) mustEmbedUnimplementedTenantServiceServer() {}

// UnsafeTenantServiceServer allows opt-out of forward compatibility. Deprecated.
type UnsafeTenantServiceServer interface {
	mustEmbedUnimplementedTenantServiceServer()
}

// RegisterTenantServiceServer registers a tenant service implementation with gRPC.
func RegisterTenantServiceServer(s grpc.ServiceRegistrar, srv TenantServiceServer) {
	s.RegisterService(&TenantService_ServiceDesc, srv)
}

// TenantService_ServiceDesc exposes the service definition to gRPC.
var TenantService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "evergreen.v1.TenantService",
	HandlerType: (*TenantServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateTenant",
			Handler:    _TenantService_CreateTenant_Handler,
		},
		{
			MethodName: "ListTenants",
			Handler:    _TenantService_ListTenants_Handler,
		},
		{
			MethodName: "RotateTenantSecret",
			Handler:    _TenantService_RotateTenantSecret_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "evergreen/v1/tenant_service.proto",
}

func _TenantService_CreateTenant_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTenantRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).CreateTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.TenantService/CreateTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).CreateTenant(ctx, req.(*CreateTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_ListTenants_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTenantsRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).ListTenants(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.TenantService/ListTenants",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).ListTenants(ctx, req.(*ListTenantsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_RotateTenantSecret_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RotateTenantSecretRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).RotateTenantSecret(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.TenantService/RotateTenantSecret",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).RotateTenantSecret(ctx, req.(*RotateTenantSecretRequest))
	}
	return interceptor(ctx, in, info, handler)
}
