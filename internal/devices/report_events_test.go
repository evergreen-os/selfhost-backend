package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestReportEventsPersistsEvents(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{}
	_ = tenantID.Scan(uuid.New().String())

	tokenManager := newDeviceTokenManager(t)
	tenantUUID, err := uuid.FromBytes(tenantID.Bytes[:])
	if err != nil {
		t.Fatalf("failed to parse tenant id: %v", err)
	}
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken("device-evt", tenantUUID.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			deviceUUID := pgtype.UUID{}
			_ = deviceUUID.Scan(uuid.New().String())
			return generated.Device{TenantID: tenantID, DeviceTokenHash: hashedToken, ID: deviceUUID}, nil
		},
		updateDeviceLastSeenFn: func(ctx context.Context, params generated.UpdateDeviceLastSeenParams) (generated.Device, error) {
			if !params.LastSeenAt.Valid {
				t.Fatal("expected valid last seen timestamp")
			}
			return generated.Device{}, nil
		},
	}

	recorder := &fakeEventsRecorder{}
	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, recorder, nil)

	now := timestamppb.New(time.Now())
	req := &pb.ReportEventsRequest{
		DeviceId:    "device-evt",
		DeviceToken: rawToken,
		BatchTime:   timestamppb.Now(),
		Events: []*pb.DeviceEvent{
			{
				EventId:   uuid.NewString(),
				DeviceId:  "device-evt",
				Type:      pb.EventType_EVENT_TYPE_SYSTEM,
				Level:     pb.EventLevel_EVENT_LEVEL_INFO,
				Timestamp: now,
				Message:   "System ready",
				Metadata: map[string]string{
					"component": "init",
				},
				UserId: "user-a",
				AppId:  "app-1",
			},
			{
				EventId:   uuid.NewString(),
				DeviceId:  "device-evt",
				Type:      pb.EventType_EVENT_TYPE_SECURITY,
				Level:     pb.EventLevel_EVENT_LEVEL_ERROR,
				Timestamp: now,
				Message:   "Security alert",
			},
		},
	}

	resp, err := service.ReportEvents(context.Background(), req)
	if err != nil {
		t.Fatalf("ReportEvents returned error: %v", err)
	}

	if resp.AcceptedEvents != int32(len(req.Events)) {
		t.Fatalf("expected %d accepted events, got %d", len(req.Events), resp.AcceptedEvents)
	}
	if resp.ServerTime == nil {
		t.Fatal("expected server time")
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("expected a single recorder invocation, got %d", len(recorder.calls))
	}
	if len(recorder.calls[0].events) != len(req.Events) {
		t.Fatalf("expected %d recorded events, got %d", len(req.Events), len(recorder.calls[0].events))
	}
}

func TestReportEventsRejectsInvalidPayload(t *testing.T) {
	t.Parallel()

	service := NewDeviceServiceWithDependencies(&fakeDeviceStore{}, &fakePolicyService{}, newDeviceTokenManager(t), &fakeEventsRecorder{}, nil)

	_, err := service.ReportEvents(context.Background(), &pb.ReportEventsRequest{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}

	badEvent := &pb.ReportEventsRequest{
		DeviceId:    "device-evt",
		DeviceToken: "token",
		Events: []*pb.DeviceEvent{{
			EventId:   "",
			Timestamp: timestamppb.Now(),
			Type:      pb.EventType_EVENT_TYPE_SYSTEM,
			Level:     pb.EventLevel_EVENT_LEVEL_INFO,
			Message:   "missing id",
		}},
	}
	_, err = service.ReportEvents(context.Background(), badEvent)
	if err == nil {
		t.Fatal("expected validation error for missing event id")
	}
}

func TestReportEventsHandlesStorageFailure(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{}
	_ = tenantID.Scan(uuid.New().String())
	tokenManager := newDeviceTokenManager(t)
	tenantUUID, err := uuid.FromBytes(tenantID.Bytes[:])
	if err != nil {
		t.Fatalf("failed to parse tenant id: %v", err)
	}
	rawToken, hashedToken, err := tokenManager.IssueDeviceToken("device-evt", tenantUUID.String())
	if err != nil {
		t.Fatalf("IssueDeviceToken error: %v", err)
	}

	store := &fakeDeviceStore{
		getDeviceByIDFn: func(ctx context.Context, deviceID string) (generated.Device, error) {
			deviceUUID := pgtype.UUID{}
			_ = deviceUUID.Scan(uuid.New().String())
			return generated.Device{TenantID: tenantID, DeviceTokenHash: hashedToken, ID: deviceUUID}, nil
		},
	}

	recorder := &fakeEventsRecorder{err: errors.New("db failure")}
	service := NewDeviceServiceWithDependencies(store, &fakePolicyService{}, tokenManager, recorder, nil)

	req := &pb.ReportEventsRequest{
		DeviceId:    "device-evt",
		DeviceToken: rawToken,
		Events: []*pb.DeviceEvent{{
			EventId:   uuid.NewString(),
			Type:      pb.EventType_EVENT_TYPE_SYSTEM,
			Level:     pb.EventLevel_EVENT_LEVEL_INFO,
			Timestamp: timestamppb.Now(),
			Message:   "System ready",
		}},
	}

	_, err = service.ReportEvents(context.Background(), req)
	if err == nil {
		t.Fatal("expected storage error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("expected internal error, got %v", err)
	}
}
