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

// Retry configuration - optimized for Render free tier (fast startup required)
const (
	maxRetries     = 3                // Reduced from 5 for faster startup
	initialBackoff = 1 * time.Second  // Reduced from 2s
	maxBackoff     = 10 * time.Second // Reduced from 30s
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
	// Create SQL DB connection with PgBouncer/Supabase Transaction Pooler compatibility
	// Disable prepared statements by using simple query protocol
	connector := pgdriver.NewConnector(
		pgdriver.WithDSN(cfg.DatabaseURL),
		pgdriver.WithDialTimeout(10*time.Second), // Faster failure detection
		pgdriver.WithReadTimeout(30*time.Second),
		pgdriver.WithWriteTimeout(30*time.Second),
	)
	sqldb := sql.OpenDB(connector)

	// Configure connection pool - optimized for Supabase Transaction Pooler
	// Transaction pooler returns connections to pool after each query,
	// so we can use fewer connections more efficiently
	sqldb.SetMaxOpenConns(3)                  // Reduced: transaction pooler shares connections
	sqldb.SetMaxIdleConns(3)                  // Match MaxOpenConns for better reuse
	sqldb.SetConnMaxLifetime(2 * time.Minute) // Shorter: recycle faster to avoid stale
	sqldb.SetConnMaxIdleTime(1 * time.Minute) // Shorter: free up pooler connections quickly

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
