package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Store describes the subset of database operations required for event ingestion.
type Store interface {
	CreateEvent(ctx context.Context, arg generated.CreateEventParams) (generated.Event, error)
	DeleteOldEvents(ctx context.Context, eventTimestamp pgtype.Timestamptz) error
}

// Service persists device events with retention enforcement.
type Service struct {
	store     Store
	retention time.Duration
	now       func() time.Time
}

const defaultRetention = 30 * 24 * time.Hour

// NewService constructs a Service instance with the provided store and retention window.
func NewService(store Store, retention time.Duration) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if retention <= 0 {
		retention = defaultRetention
	}
	return &Service{store: store, retention: retention, now: time.Now}, nil
}

// WithClock overrides the internal clock for deterministic testing.
func (s *Service) WithClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// IngestBatch validates and stores a collection of events for the given device record.
func (s *Service) IngestBatch(ctx context.Context, device generated.Device, events []*pb.DeviceEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	cutoff := s.now().UTC().Add(-s.retention)
	if err := s.store.DeleteOldEvents(ctx, pgtype.Timestamptz{Time: cutoff, Valid: true}); err != nil {
		return 0, fmt.Errorf("cleanup old events: %w", err)
	}
	accepted := 0
	for _, event := range events {
		if event == nil {
			return 0, fmt.Errorf("event payload is nil")
		}
		params, err := s.buildParams(device, event)
		if err != nil {
			return 0, err
		}
		if _, err := s.store.CreateEvent(ctx, params); err != nil {
			return 0, fmt.Errorf("create event: %w", err)
		}
		accepted++
	}
	return accepted, nil
}

func (s *Service) buildParams(device generated.Device, event *pb.DeviceEvent) (generated.CreateEventParams, error) {
	if event.Timestamp == nil {
		return generated.CreateEventParams{}, fmt.Errorf("event timestamp is required")
	}
	timestamp := event.Timestamp.AsTime()
	if timestamp.IsZero() {
		return generated.CreateEventParams{}, fmt.Errorf("event timestamp is invalid")
	}
	if event.Message == "" {
		return generated.CreateEventParams{}, fmt.Errorf("event message is required")
	}
	metadata := map[string]string{}
	if event.Metadata != nil {
		metadata = event.Metadata
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return generated.CreateEventParams{}, fmt.Errorf("marshal metadata: %w", err)
	}
	eventID, err := ensureEventUUID(event.EventId)
	if err != nil {
		return generated.CreateEventParams{}, err
	}
	return generated.CreateEventParams{
		EventID:        eventID,
		DeviceID:       device.ID,
		EventType:      mapEventType(event.Type),
		EventLevel:     mapEventLevel(event.Level),
		Message:        event.Message,
		Metadata:       metadataJSON,
		UserID:         optionalString(event.UserId),
		AppID:          optionalString(event.AppId),
		PolicyID:       nil,
		ErrorDetails:   nil,
		DurationMs:     nil,
		EventTimestamp: pgtype.Timestamptz{Time: timestamp, Valid: true},
	}, nil
}

func ensureEventUUID(eventID string) (string, error) {
	if _, err := uuid.Parse(eventID); err == nil {
		return eventID, nil
	}
	generatedID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}
	return generatedID.String(), nil
}

func mapEventType(eventType pb.EventType) string {
	switch eventType {
	case pb.EventType_EVENT_TYPE_SYSTEM:
		return "system"
	case pb.EventType_EVENT_TYPE_APPLICATION:
		return "application"
	case pb.EventType_EVENT_TYPE_SECURITY:
		return "security"
	case pb.EventType_EVENT_TYPE_POLICY:
		return "policy"
	case pb.EventType_EVENT_TYPE_APP_INSTALL:
		return "app_install"
	default:
		return "unknown"
	}
}

func mapEventLevel(level pb.EventLevel) string {
	switch level {
	case pb.EventLevel_EVENT_LEVEL_WARNING:
		return "warn"
	case pb.EventLevel_EVENT_LEVEL_ERROR, pb.EventLevel_EVENT_LEVEL_CRITICAL:
		return "error"
	default:
		return "info"
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	v := value
	return &v
}
