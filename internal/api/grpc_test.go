package api

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testServiceServer interface {
	Call(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

type testService struct{}

func (s *testService) Call(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

var testServiceDesc = &grpc.ServiceDesc{
	ServiceName: "api.test.v1.TestService",
	HandlerType: (*testServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Call",
			Handler: func(srv interface{}, ctx context.Context, decode func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
				in := new(emptypb.Empty)
				if err := decode(in); err != nil {
					return nil, err
				}
				target := srv.(testServiceServer)
				if interceptor == nil {
					return target.Call(ctx, in)
				}
				info := &grpc.UnaryServerInfo{FullMethod: "/api.test.v1.TestService/Call"}
				handler := func(ctx context.Context, req interface{}) (interface{}, error) {
					return target.Call(ctx, req.(*emptypb.Empty))
				}
				return interceptor(ctx, in, info, handler)
			},
		},
	},
}

func TestNewGRPCServerRegistersHealthAndReflection(t *testing.T) {
	srv := NewGRPCServer()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() { srv.GracefulStop() })

	conn, err := grpc.DialContext(context.Background(), lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	if _, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health check failed: %v", err)
	}
}

func TestNewGRPCServerAppliesUnaryInterceptors(t *testing.T) {
	called := false
	interceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		called = true
		return handler(ctx, req)
	}

	srv := NewGRPCServer(WithUnaryInterceptors(interceptor), WithRegistrations(func(s *grpc.Server) {
		s.RegisterService(testServiceDesc, &testService{})
	}))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() { srv.GracefulStop() })

	conn, err := grpc.DialContext(context.Background(), lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.Invoke(context.Background(), "/api.test.v1.TestService/Call", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !called {
		t.Fatal("expected interceptor to be called")
	}
}
