package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`server:
  grpc_port: 1111
  rest_port: 2222

database:
  host: db.local
  port: 5433
  name: evergreen
  user: admin
  password: secret
  ssl_mode: disable

metrics:
  enabled: true
  port: 3333
  path: /metrics
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.GRPCPort != 1111 {
		t.Fatalf("unexpected gRPC port: %d", cfg.Server.GRPCPort)
	}
	if cfg.Database.Host != "db.local" {
		t.Fatalf("unexpected db host: %s", cfg.Database.Host)
	}
	if got := cfg.Database.DSN(); got != "postgres://admin:secret@db.local:5433/evergreen?sslmode=disable" {
		t.Fatalf("unexpected DSN: %s", got)
	}
	if !cfg.Metrics.Enabled || cfg.Metrics.Port != 3333 {
		t.Fatalf("unexpected metrics config: %+v", cfg.Metrics)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := Load("/path/does/not/exist.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDatabaseDSNOmitsPasswordWhenEmpty(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{
			Host:    "localhost",
			Port:    5432,
			Name:    "evergreen",
			User:    "service",
			SSLMode: "require",
		},
	}

	if got := cfg.Database.DSN(); got != "postgres://service@localhost:5432/evergreen?sslmode=require" {
		t.Fatalf("unexpected DSN: %s", got)
	}
}
