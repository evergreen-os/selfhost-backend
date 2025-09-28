package evergreenv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PolicyServiceServer defines admin policy management RPCs.
type PolicyServiceServer interface {
	CreatePolicy(context.Context, *CreatePolicyRequest) (*CreatePolicyResponse, error)
	UpdatePolicy(context.Context, *UpdatePolicyRequest) (*UpdatePolicyResponse, error)
	DeletePolicy(context.Context, *DeletePolicyRequest) (*DeletePolicyResponse, error)
	GetPolicy(context.Context, *GetPolicyRequest) (*GetPolicyResponse, error)
	ListPolicies(context.Context, *ListPoliciesRequest) (*ListPoliciesResponse, error)
	mustEmbedUnimplementedPolicyServiceServer()
}

// UnimplementedPolicyServiceServer provides forward compatible stubs.
type UnimplementedPolicyServiceServer struct{}

// CreatePolicy implements the PolicyServiceServer interface for forward compatibility.
func (UnimplementedPolicyServiceServer) CreatePolicy(context.Context, *CreatePolicyRequest) (*CreatePolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreatePolicy not implemented")
}

// UpdatePolicy implements the PolicyServiceServer interface for forward compatibility.
func (UnimplementedPolicyServiceServer) UpdatePolicy(context.Context, *UpdatePolicyRequest) (*UpdatePolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "UpdatePolicy not implemented")
}

// DeletePolicy implements the PolicyServiceServer interface for forward compatibility.
func (UnimplementedPolicyServiceServer) DeletePolicy(context.Context, *DeletePolicyRequest) (*DeletePolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "DeletePolicy not implemented")
}

// GetPolicy implements the PolicyServiceServer interface for forward compatibility.
func (UnimplementedPolicyServiceServer) GetPolicy(context.Context, *GetPolicyRequest) (*GetPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetPolicy not implemented")
}

// ListPolicies implements the PolicyServiceServer interface for forward compatibility.
func (UnimplementedPolicyServiceServer) ListPolicies(context.Context, *ListPoliciesRequest) (*ListPoliciesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListPolicies not implemented")
}

// mustEmbedUnimplementedPolicyServiceServer enforces forward compatibility.
func (UnimplementedPolicyServiceServer) mustEmbedUnimplementedPolicyServiceServer() {}

// UnsafePolicyServiceServer allows opt-out of forward compatibility. Deprecated.
type UnsafePolicyServiceServer interface {
	mustEmbedUnimplementedPolicyServiceServer()
}

// RegisterPolicyServiceServer registers a policy service implementation with gRPC.
func RegisterPolicyServiceServer(s grpc.ServiceRegistrar, srv PolicyServiceServer) {
	s.RegisterService(&PolicyService_ServiceDesc, srv)
}

// PolicyService_ServiceDesc exposes the service definition to gRPC.
var PolicyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "evergreen.v1.PolicyService",
	HandlerType: (*PolicyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreatePolicy",
			Handler:    _PolicyService_CreatePolicy_Handler,
		},
		{
			MethodName: "UpdatePolicy",
			Handler:    _PolicyService_UpdatePolicy_Handler,
		},
		{
			MethodName: "DeletePolicy",
			Handler:    _PolicyService_DeletePolicy_Handler,
		},
		{
			MethodName: "GetPolicy",
			Handler:    _PolicyService_GetPolicy_Handler,
		},
		{
			MethodName: "ListPolicies",
			Handler:    _PolicyService_ListPolicies_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "evergreen/v1/policy_service.proto",
}

func _PolicyService_CreatePolicy_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePolicyRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.PolicyService/CreatePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, req.(*CreatePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_UpdatePolicy_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePolicyRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).UpdatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.PolicyService/UpdatePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).UpdatePolicy(ctx, req.(*UpdatePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_DeletePolicy_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeletePolicyRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.PolicyService/DeletePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, req.(*DeletePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_GetPolicy_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPolicyRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).GetPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.PolicyService/GetPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).GetPolicy(ctx, req.(*GetPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_ListPolicies_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPoliciesRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).ListPolicies(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.PolicyService/ListPolicies",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).ListPolicies(ctx, req.(*ListPoliciesRequest))
	}
	return interceptor(ctx, in, info, handler)
}
