package db

import (
	"context"
	"fmt"

	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the database connection and queries
type DB struct {
	pool    *pgxpool.Pool
	queries *generated.Queries
}

// New creates a new database instance
func New(ctx context.Context, databaseURL string) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool
	config.MaxConns = 25
	config.MinConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	queries := generated.New(pool)

	return &DB{
		pool:    pool,
		queries: queries,
	}, nil
}

// Close closes the database connection pool
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
}

// Queries returns the generated queries instance
func (db *DB) Queries() *generated.Queries {
	return db.queries
}

// Pool returns the connection pool for transactions
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// WithTx executes a function within a database transaction
func (db *DB) WithTx(ctx context.Context, fn func(*generated.Queries) error) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := db.queries.WithTx(tx)
	if err := fn(qtx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}