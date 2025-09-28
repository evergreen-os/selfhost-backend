package events

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeStore struct {
	created   []generated.CreateEventParams
	deletedAt []pgtype.Timestamptz
	err       error
}

func (f *fakeStore) CreateEvent(ctx context.Context, arg generated.CreateEventParams) (generated.Event, error) {
	if f.err != nil {
		return generated.Event{}, f.err
	}
	f.created = append(f.created, arg)
	return generated.Event{EventID: arg.EventID}, nil
}

func (f *fakeStore) DeleteOldEvents(ctx context.Context, ts pgtype.Timestamptz) error {
	if f.err != nil {
		return f.err
	}
	f.deletedAt = append(f.deletedAt, ts)
	return nil
}

func TestNewServiceValidatesStore(t *testing.T) {
	if _, err := NewService(nil, time.Hour); err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestIngestBatchValidatesEvents(t *testing.T) {
	svc, _ := NewService(&fakeStore{}, time.Hour)
	device := generated.Device{ID: pgtype.UUID{Bytes: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Valid: true}}
	if _, err := svc.IngestBatch(context.Background(), device, []*pb.DeviceEvent{{}}); err == nil {
		t.Fatal("expected validation error for missing timestamp")
	}
}

func TestIngestBatchPersistsEvents(t *testing.T) {
	store := &fakeStore{}
	svc, _ := NewService(store, 24*time.Hour)
	now := time.Now()
	svc.WithClock(func() time.Time { return now })
	device := generated.Device{ID: pgtype.UUID{Bytes: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Valid: true}}
	events := []*pb.DeviceEvent{{
		EventId:   uuid.NewString(),
		Type:      pb.EventType_EVENT_TYPE_SYSTEM,
		Level:     pb.EventLevel_EVENT_LEVEL_INFO,
		Message:   "boot completed",
		Timestamp: timestamppb.New(now.Add(-time.Minute)),
	}}
	accepted, err := svc.IngestBatch(context.Background(), device, events)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if accepted != 1 {
		t.Fatalf("expected 1 accepted event got %d", accepted)
	}
	if len(store.deletedAt) != 1 {
		t.Fatalf("expected retention cleanup to run")
	}
	if len(store.created) != 1 {
		t.Fatalf("expected a persisted event")
	}
	if store.created[0].Message != "boot completed" {
		t.Fatalf("unexpected message: %s", store.created[0].Message)
	}
}

func TestIngestBatchPropagatesStoreErrors(t *testing.T) {
	store := &fakeStore{err: errors.New("boom")}
	svc, _ := NewService(store, time.Hour)
	device := generated.Device{ID: pgtype.UUID{Bytes: uuid.MustParse("33333333-3333-3333-3333-333333333333"), Valid: true}}
	events := []*pb.DeviceEvent{{
		EventId:   uuid.NewString(),
		Message:   "crash",
		Timestamp: timestamppb.Now(),
	}}
	if _, err := svc.IngestBatch(context.Background(), device, events); err == nil {
		t.Fatal("expected error from store")
	}
}
