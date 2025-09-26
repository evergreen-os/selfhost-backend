# EvergreenOS Selfhost Backend Makefile

.PHONY: gen build test lint clean docker-build docker-up docker-down migrate-up migrate-down

# Go build settings
GO_VERSION := 1.23
BINARY_NAME := selfhost-backend
MIGRATE_BINARY := migrate-tool

# Directories
BIN_DIR := bin
GEN_DIR := gen
MIGRATIONS_DIR := migrations

# Database settings
DB_URL := postgres://evergreen:password@localhost:5432/evergreen_selfhost?sslmode=disable

# Build targets
build:
	@echo "Building server..."
	go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/server
	@echo "Building migrate tool..."
	go build -o $(BIN_DIR)/$(MIGRATE_BINARY) ./cmd/migrate

# Code generation from shared-specs
gen:
	@echo "Generating code from shared-specs..."
	buf generate ../shared-specs
	@echo "Generating sqlc queries..."
	sqlc generate

# Testing
test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# Linting
lint:
	golangci-lint run

# Development database
db-start:
	docker run -d --name evergreen-postgres \
		-e POSTGRES_USER=evergreen \
		-e POSTGRES_PASSWORD=password \
		-e POSTGRES_DB=evergreen_selfhost \
		-p 5432:5432 \
		postgres:14

db-stop:
	docker stop evergreen-postgres
	docker rm evergreen-postgres

# Migrations
migrate-up:
	$(BIN_DIR)/$(MIGRATE_BINARY) up

migrate-down:
	$(BIN_DIR)/$(MIGRATE_BINARY) down

migrate-create:
	@read -p "Migration name: " name; \
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $$name

# Docker
docker-build:
	docker build -t evergreenos/selfhost-backend .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Cleanup
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(GEN_DIR)

# Install tools
install-tools:
	go install github.com/golang/protobuf/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest