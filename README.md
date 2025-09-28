# EvergreenOS Selfhost Backend

EvergreenOS Selfhost Backend is the reference control plane for managing Evergreen client devices. It exposes both REST and gRPC services for enrollment, policy distribution, device state reporting, and administrator workflows while persisting data to PostgreSQL. The project follows the Evergreen shared-specs contracts and ships with SQL migrations, policy signing, auditing, and metrics so that operators can run it in their own infrastructure.

## Features

- **Device lifecycle management** – gRPC and REST handlers cover enrollment, policy pulls, state uploads, attestation, and event ingestion using the generated Evergreen protobuf APIs.
- **Administrator workflows** – Admin, policy, and tenant management services enforce JWT-based RBAC controls, allow policy CRUD operations, and surface paginated listings for console integrations.
- **Persistence layer** – SQL migrations create tables for tenants, users, devices, policy bundles, device state snapshots, events, and immutable audit logs together with helpful indexes.
- **Policy signing** – Policies are stored as versioned bundles and signed with Ed25519 keys so devices can validate authenticity.
- **Observability** – All API layers emit audit records for important operations and publish Prometheus metrics under `/metrics` when enabled.

## Repository layout

```
cmd/            # Command binaries (server, migrate)
config/         # Example YAML configuration
internal/       # Application logic grouped by domain
migrations/     # SQL migrations executed by the migrate tool
server/         # Container image and deployment helpers
```

Generated gRPC and database bindings live under `gen/` after running the code generation workflow described below.

## Prerequisites

- Go 1.23 or newer
- A PostgreSQL 14+ instance accessible to the backend
- `buf`, `sqlc`, and `golang-migrate` CLI tools (see `make install-tools`)
- Optional: Docker and Docker Compose for local database or container workflows

## Configuration

The server loads configuration from a YAML file (default: `config/config.yaml`). Key options include:

| Section | Keys | Description |
| ------- | ---- | ----------- |
| `server` | `grpc_port`, `rest_port`, `tls_cert_file`, `tls_key_file` | Listener ports and optional TLS material |
| `database` | `host`, `port`, `name`, `user`, `password`, `ssl_mode`, `max_connections` | PostgreSQL connection settings used to build the DSN |
| `auth` | `jwt_secret`, `jwt_expiry_hours`, `device_token_expiry_hours` | JWT signing secret and expiry windows |
| `policy` | `signing_key_path`, `signing_key_id` | Ed25519 key used to sign policy bundles |
| `logging` | `level`, `format` | Configure slog level and JSON/text output |
| `metrics` | `enabled`, `port`, `path` | Toggle Prometheus endpoint exposure |
| `attestation` | `enabled`, `quote_ttl_seconds` | Control TPM attestation verification |

Environment variables can override the configuration path via `-config` when starting the server. The migration command also accepts `--database-url` and `--migrations-dir` flags.

## Building and testing

```bash
make build          # Compile the server and migration binaries into ./bin
make test           # Run the full Go test suite
```

To regenerate protobuf and SQL client code, run:

```bash
make gen
```

## Database migrations

The `cmd/migrate` binary wraps the migration helpers in `internal/db`. Build it via `make build` and execute migrations against your database:

```bash
./bin/migrate-tool --database-url <postgres-url> --command up
./bin/migrate-tool --database-url <postgres-url> --command down
./bin/migrate-tool --database-url <postgres-url> --command version
```

The shipped migrations create all primary tables and indexes. Custom migrations can be added with `make migrate-create`.

## Running the server

```bash
./bin/selfhost-backend -config config/config.yaml
```

The server starts gRPC, REST, and metrics listeners (when enabled). By default it serves:

- REST APIs on `http://localhost:8080`
- gRPC APIs on `localhost:9090`
- Prometheus metrics on `http://localhost:9091/metrics`

Use `docker-compose up` to launch the service alongside supporting containers if you prefer Docker-based development.

## API surfaces

- **REST** – `/v1/devices` for device enrollment, state, events, and policy pulls; `/v1/admin` for user, policy, and tenant administration. All responses are JSON and support pagination tokens where applicable.
- **gRPC** – Device, Admin, Policy, and Tenant services generated from the shared-specs definitions. The server registers standard gRPC health checking and reflection for tooling support.

Refer to the `openapi/evergreen.v1.yaml` and protobuf contracts in the `shared-specs` repository for detailed request/response schemas.

## Observability and auditing

Every administrator action and device operation flows through the audit subsystem, and Prometheus metrics expose request counters, latencies, and error rates. Integrate the `/metrics` endpoint with your monitoring stack and ship audit logs to a SIEM for long-term retention.

## Development tips

- Use `make db-start` to spin up a local PostgreSQL container, and `make db-stop` to tear it down.
- Generate signing keys for policies with `openssl` or `age-keygen`, then configure the key path in `config.yaml`.
- Enable attestation once TPM attesters are available by providing quote TTL and verifying material in configuration.

## License

This project is released under the Apache 2.0 license.
