package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/evergreenos/selfhost-backend/internal/db"
)

func main() {
	var (
		dbURL         = flag.String("database-url", os.Getenv("DATABASE_URL"), "Database connection URL")
		migrationsDir = flag.String("migrations-dir", "migrations", "Path to migrations directory")
		command       = flag.String("command", "up", "Command to run: up, down, version")
	)
	flag.Parse()

	if *dbURL == "" {
		*dbURL = "postgres://evergreen:password@localhost:5432/evergreen_selfhost?sslmode=disable"
	}

	// Get absolute path to migrations
	migPath, err := filepath.Abs(*migrationsDir)
	if err != nil {
		log.Fatalf("Failed to get absolute path to migrations: %v", err)
	}

	log.Printf("EvergreenOS Database Migration Tool")
	log.Printf("Command: %s", *command)
	log.Printf("Database URL: %s", *dbURL)
	log.Printf("Migrations Directory: %s", migPath)

	switch *command {
	case "up":
		if err := db.MigrateUp(*dbURL, migPath); err != nil {
			log.Fatalf("Failed to run migrations up: %v", err)
		}
		log.Println("Migrations completed successfully")

	case "down":
		if err := db.MigrateDown(*dbURL, migPath); err != nil {
			log.Fatalf("Failed to run migration down: %v", err)
		}
		log.Println("Migration rollback completed successfully")

	case "version":
		version, dirty, err := db.MigrateVersion(*dbURL, migPath)
		if err != nil {
			log.Fatalf("Failed to get migration version: %v", err)
		}
		fmt.Printf("Current migration version: %d (dirty: %t)\n", version, dirty)

	default:
		log.Fatalf("Unknown command: %s (valid commands: up, down, version)", *command)
	}
}