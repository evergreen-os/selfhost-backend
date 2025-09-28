package evergreenv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DeviceServiceServer defines the EvergreenOS device lifecycle gRPC API.
type DeviceServiceServer interface {
	EnrollDevice(context.Context, *EnrollDeviceRequest) (*EnrollDeviceResponse, error)
	PullPolicy(context.Context, *PullPolicyRequest) (*PullPolicyResponse, error)
	ReportState(context.Context, *ReportStateRequest) (*ReportStateResponse, error)
	ReportEvents(context.Context, *ReportEventsRequest) (*ReportEventsResponse, error)
	AttestBoot(context.Context, *AttestBootRequest) (*AttestBootResponse, error)
	mustEmbedUnimplementedDeviceServiceServer()
}

// RegisterDeviceServiceServer wires a DeviceService implementation into the provided server registrar.
func RegisterDeviceServiceServer(s grpc.ServiceRegistrar, srv DeviceServiceServer) {
	s.RegisterService(&DeviceService_ServiceDesc, srv)
}

// DeviceService_ServiceDesc exposes the EvergreenOS device lifecycle RPC definitions to gRPC.
var DeviceService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "evergreen.v1.DeviceService",
	HandlerType: (*DeviceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "EnrollDevice",
			Handler:    _DeviceService_EnrollDevice_Handler,
		},
		{
			MethodName: "PullPolicy",
			Handler:    _DeviceService_PullPolicy_Handler,
		},
		{
			MethodName: "ReportState",
			Handler:    _DeviceService_ReportState_Handler,
		},
		{
			MethodName: "ReportEvents",
			Handler:    _DeviceService_ReportEvents_Handler,
		},
		{
			MethodName: "AttestBoot",
			Handler:    _DeviceService_AttestBoot_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "evergreen/v1/device_service.proto",
}

func _DeviceService_EnrollDevice_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnrollDeviceRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceServiceServer).EnrollDevice(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.DeviceService/EnrollDevice",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceServiceServer).EnrollDevice(ctx, req.(*EnrollDeviceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceService_PullPolicy_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PullPolicyRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceServiceServer).PullPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.DeviceService/PullPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceServiceServer).PullPolicy(ctx, req.(*PullPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceService_ReportState_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReportStateRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceServiceServer).ReportState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.DeviceService/ReportState",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceServiceServer).ReportState(ctx, req.(*ReportStateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceService_ReportEvents_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReportEventsRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceServiceServer).ReportEvents(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.DeviceService/ReportEvents",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceServiceServer).ReportEvents(ctx, req.(*ReportEventsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceService_AttestBoot_Handler(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestBootRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceServiceServer).AttestBoot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/evergreen.v1.DeviceService/AttestBoot",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceServiceServer).AttestBoot(ctx, req.(*AttestBootRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EnrollDevice implements the DeviceServiceServer interface for forward compatibility.
func (UnimplementedDeviceServiceServer) EnrollDevice(context.Context, *EnrollDeviceRequest) (*EnrollDeviceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "EnrollDevice not implemented")
}

// PullPolicy implements the DeviceServiceServer interface for forward compatibility.
func (UnimplementedDeviceServiceServer) PullPolicy(context.Context, *PullPolicyRequest) (*PullPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PullPolicy not implemented")
}

// ReportState implements the DeviceServiceServer interface for forward compatibility.
func (UnimplementedDeviceServiceServer) ReportState(context.Context, *ReportStateRequest) (*ReportStateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ReportState not implemented")
}

// ReportEvents implements the DeviceServiceServer interface for forward compatibility.
func (UnimplementedDeviceServiceServer) ReportEvents(context.Context, *ReportEventsRequest) (*ReportEventsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ReportEvents not implemented")
}

// AttestBoot implements the DeviceServiceServer interface for forward compatibility.
func (UnimplementedDeviceServiceServer) AttestBoot(context.Context, *AttestBootRequest) (*AttestBootResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AttestBoot not implemented")
}

// mustEmbedUnimplementedDeviceServiceServer enforces forward compatibility.
func (UnimplementedDeviceServiceServer) mustEmbedUnimplementedDeviceServiceServer() {}

// UnsafeDeviceServiceServer may be embedded to opt out of forward compatible implementations. Deprecated.
type UnsafeDeviceServiceServer interface {
	mustEmbedUnimplementedDeviceServiceServer()
}
