package evergreenv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AdminServiceServer defines admin management RPCs for Evergreen.
type AdminServiceServer interface {
	Login(context.Context, *AdminLoginRequest) (*AdminLoginResponse, error)
	CreateUser(context.Context, *CreateAdminUserRequest) (*CreateAdminUserResponse, error)
	ListUsers(context.Context, *ListAdminUsersRequest) (*ListAdminUsersResponse, error)
	mustEmbedUnimplementedAdminServiceServer()
}

// UnimplementedAdminServiceServer provides forward compatible method stubs.
type UnimplementedAdminServiceServer struct{}

// Login implements the AdminServiceServer interface for forward compatibility.
func (UnimplementedAdminServiceServer) Login(context.Context, *AdminLoginRequest) (*AdminLoginResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Login not implemented")
}

// CreateUser implements the AdminServiceServer interface for forward compatibility.
func (UnimplementedAdminServiceServer) CreateUser(context.Context, *CreateAdminUserRequest) (*CreateAdminUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateUser not implemented")
}

// ListUsers implements the AdminServiceServer interface for forward compatibility.
func (UnimplementedAdminServiceServer) ListUsers(context.Context, *ListAdminUsersRequest) (*ListAdminUsersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListUsers not implemented")
}

// mustEmbedUnimplementedAdminServiceServer enforces forward compatibility.
func (UnimplementedAdminServiceServer) mustEmbedUnimplementedAdminServiceServer() {}

// UnsafeAdminServiceServer allows opt-out of forward compatibility. Deprecated.
type UnsafeAdminServiceServer interface {
	mustEmbedUnimplementedAdminServiceServer()
}

// RegisterAdminServiceServer registers an admin service implementation with gRPC.
func RegisterAdminServiceServer(s grpc.ServiceRegistrar, srv AdminServiceServer) {
	s.RegisterService(&AdminService_ServiceDesc, srv)
}

// AdminService_ServiceDesc exposes the service definition to gRPC.
var AdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "evergreen.v1.AdminService",
	HandlerType: (*AdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _AdminService_Login_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _AdminService_CreateUser_Handler,
		},
		{
			MethodName: "ListUsers",
			Handler:    _AdminService_ListUsers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "evergreen/v1/admin_service.proto",
}

func _AdminService_Login_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AdminLoginRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.AdminService/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).Login(ctx, req.(*AdminLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdminService_CreateUser_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAdminUserRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).CreateUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.AdminService/CreateUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).CreateUser(ctx, req.(*CreateAdminUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdminService_ListUsers_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAdminUsersRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).ListUsers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.AdminService/ListUsers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).ListUsers(ctx, req.(*ListAdminUsersRequest))
	}
	return interceptor(ctx, in, info, handler)
}
