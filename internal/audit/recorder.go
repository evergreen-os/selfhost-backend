package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const insertAuditLogSQL = `INSERT INTO audit_logs (
        id,
        correlation_id,
        actor_type,
        actor_id,
        tenant_id,
        action,
        resource_type,
        resource_id,
        details,
        ip_address,
        user_agent,
        created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

// ExecCommander is implemented by pgx pools and connections capable of executing SQL commands.
type ExecCommander interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Entry captures a single immutable audit log event.
type Entry struct {
	CorrelationID uuid.UUID
	ActorType     string
	ActorID       string
	TenantID      *uuid.UUID
	Action        string
	ResourceType  string
	ResourceID    string
	Details       map[string]any
	IPAddress     string
	UserAgent     string
	OccurredAt    time.Time
}

// Recorder persists immutable audit events for compliance tracking.
type Recorder struct {
	store ExecCommander
}

// NewRecorder constructs a Recorder backed by the provided ExecCommander implementation.
func NewRecorder(store ExecCommander) (*Recorder, error) {
	if store == nil {
		return nil, fmt.Errorf("audit store is required")
	}
	return &Recorder{store: store}, nil
}

// Record validates and inserts the supplied audit entry.
func (r *Recorder) Record(ctx context.Context, entry Entry) error {
	if entry.ActorType == "" {
		return fmt.Errorf("actor type is required")
	}
	if entry.ActorID == "" {
		return fmt.Errorf("actor id is required")
	}
	if entry.Action == "" {
		return fmt.Errorf("action is required")
	}
	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = time.Now().UTC()
	}
	correlationID := entry.CorrelationID
	if correlationID == uuid.Nil {
		correlationID = uuid.New()
	}
	detailsJSON, err := json.Marshal(entry.Details)
	if err != nil {
		return fmt.Errorf("marshal details: %w", err)
	}
	var tenantID any
	if entry.TenantID != nil {
		tenantID = entry.TenantID
	} else {
		tenantID = nil
	}
	var ip any
	if entry.IPAddress != "" {
		if net.ParseIP(entry.IPAddress) == nil {
			return fmt.Errorf("ip address invalid")
		}
		ip = entry.IPAddress
	}
        _, err = r.store.Exec(ctx, insertAuditLogSQL,
                uuid.New(),
                correlationID,
                entry.ActorType,
                entry.ActorID,
                tenantID,
		entry.Action,
		nullIfEmpty(entry.ResourceType),
		nullIfEmpty(entry.ResourceID),
		detailsJSON,
		ip,
                nullIfEmpty(entry.UserAgent),
                entry.OccurredAt,
        )
        if err != nil {
                return fmt.Errorf("insert audit log: %w", err)
        }
        return nil
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
