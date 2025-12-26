package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/boscod/responsewatch/config"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

var DB *bun.DB

// Retry configuration
const (
	maxRetries     = 5
	initialBackoff = 2 * time.Second
	maxBackoff     = 30 * time.Second
	backoffFactor  = 2
)

func Connect(cfg *config.Config) (*bun.DB, error) {
	var db *bun.DB
	var lastErr error
	backoff := initialBackoff

	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, lastErr = attemptConnect(cfg)
		if lastErr == nil {
			if attempt > 1 {
				log.Printf("Successfully connected to database on attempt %d", attempt)
			}
			DB = db
			return db, nil
		}

		log.Printf("Database connection attempt %d/%d failed: %v", attempt, maxRetries, lastErr)

		if attempt < maxRetries {
			log.Printf("Retrying in %v...", backoff)
			time.Sleep(backoff)

			// Exponential backoff with max limit
			backoff *= backoffFactor
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, lastErr)
}

func attemptConnect(cfg *config.Config) (*bun.DB, error) {
	// Create SQL DB connection
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(cfg.DatabaseURL)))

	// Configure connection pool
	sqldb.SetMaxOpenConns(25)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(5 * time.Minute)

	// Create Bun DB instance
	db := bun.NewDB(sqldb, pgdialect.New())

	// Test connection with longer timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		// Close the connection if ping fails
		sqldb.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}
