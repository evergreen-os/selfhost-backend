package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeExec struct {
	lastSQL  string
	lastArgs []any
	err      error
}

func (f *fakeExec) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.lastSQL = sql
	f.lastArgs = args
	if f.err != nil {
		return pgconn.CommandTag{}, f.err
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestNewRecorderValidatesStore(t *testing.T) {
	if _, err := NewRecorder(nil); err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestRecordValidatesRequiredFields(t *testing.T) {
	recorder, _ := NewRecorder(&fakeExec{})
	cases := []Entry{
		{},
		{ActorType: "user"},
		{ActorType: "user", ActorID: "1"},
	}
	for _, entry := range cases {
		if err := recorder.Record(context.Background(), entry); err == nil {
			t.Fatalf("expected validation error for entry %#v", entry)
		}
	}
}

func TestRecordInsertsAuditLog(t *testing.T) {
	store := &fakeExec{}
	recorder, _ := NewRecorder(store)
	tenantID := uuid.New()
	entry := Entry{
		ActorType: "user",
		ActorID:   "admin-1",
		Action:    "policy.create",
		TenantID:  &tenantID,
		Details:   map[string]any{"policy_id": "p1"},
		IPAddress: "127.0.0.1",
	}
	if err := recorder.Record(context.Background(), entry); err != nil {
		t.Fatalf("record: %v", err)
	}
	if store.lastSQL != insertAuditLogSQL {
		t.Fatalf("unexpected sql: %s", store.lastSQL)
	}
	if len(store.lastArgs) != 12 {
		t.Fatalf("expected 12 args got %d", len(store.lastArgs))
	}
	if _, ok := store.lastArgs[0].(uuid.UUID); !ok {
		t.Fatalf("expected first arg to be uuid")
	}
	if _, ok := store.lastArgs[1].(uuid.UUID); !ok {
		t.Fatalf("expected correlation id to be uuid")
	}
	if store.lastArgs[9] != entry.IPAddress {
		t.Fatalf("expected ip address to be set")
	}
	if _, ok := store.lastArgs[11].(time.Time); !ok {
		t.Fatalf("expected timestamp argument")
	}
}

func TestRecordPropagatesStoreError(t *testing.T) {
	store := &fakeExec{err: errors.New("boom")}
	recorder, _ := NewRecorder(store)
	entry := Entry{ActorType: "user", ActorID: "u1", Action: "login"}
	if err := recorder.Record(context.Background(), entry); err == nil {
		t.Fatal("expected error when store fails")
	}
}

func TestRecordValidatesIPAddress(t *testing.T) {
	recorder, _ := NewRecorder(&fakeExec{})
	entry := Entry{ActorType: "user", ActorID: "u1", Action: "update", IPAddress: "not-an-ip"}
	if err := recorder.Record(context.Background(), entry); err == nil {
		t.Fatal("expected ip validation error")
	}
}
