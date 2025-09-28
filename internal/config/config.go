package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the EvergreenOS backend configuration structure.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Database    DatabaseConfig    `yaml:"database"`
	Auth        AuthConfig        `yaml:"auth"`
	Policy      PolicyConfig      `yaml:"policy"`
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Attestation AttestationConfig `yaml:"attestation"`
}

// ServerConfig controls listener ports and TLS assets.
type ServerConfig struct {
	GRPCPort    int    `yaml:"grpc_port"`
	RESTPort    int    `yaml:"rest_port"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

// DatabaseConfig describes Postgres connectivity options.
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"ssl_mode"`
	MaxConns int32  `yaml:"max_connections"`
}

// AuthConfig configures JWT issuance.
type AuthConfig struct {
	JWTSecret            string `yaml:"jwt_secret"`
	JWTExpiryHours       int    `yaml:"jwt_expiry_hours"`
	DeviceTokenExpiryHrs int    `yaml:"device_token_expiry_hours"`
}

// PolicyConfig configures signing for policy bundles.
type PolicyConfig struct {
	SigningKeyPath string `yaml:"signing_key_path"`
	SigningKeyID   string `yaml:"signing_key_id"`
}

// LoggingConfig controls logging verbosity and formatting.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig controls Prometheus exposure.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// AttestationConfig controls TPM attestation behaviour.
type AttestationConfig struct {
	Enabled         bool `yaml:"enabled"`
	QuoteTTLSeconds int  `yaml:"quote_ttl_seconds"`
}

// Load reads configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %q not found: %w", path, err)
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	return &cfg, nil
}

// DSN builds a Postgres connection string for pgx.
func (c DatabaseConfig) DSN() string {
	host := c.Host
	if host == "" {
		host = "localhost"
	}
	port := c.Port
	if port == 0 {
		port = 5432
	}
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}

	u := &url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   c.Name,
	}

	if c.User != "" {
		if c.Password != "" {
			u.User = url.UserPassword(c.User, c.Password)
		} else {
			u.User = url.User(c.User)
		}
	}

	q := url.Values{}
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()

	return u.String()
}
