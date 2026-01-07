package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port string
	Env  string

	// Database
	DatabaseURL string
	RabbitMQURL string

	// Security
	JWTSecret     string
	SessionSecret string
	AppSecret     string // For AES encryption

	// CORS
	AllowedOrigins []string

	// Session
	SessionExpiry time.Duration
}

var AppConfig *Config

func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if not found)
	_ = godotenv.Load()

	sessionExpiryHours, _ := strconv.Atoi(getEnv("SESSION_EXPIRY_HOURS", "168"))

	config := &Config{
		Port:           getEnv("PORT", "3000"),
		Env:            getEnv("ENV", "development"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/response_watch?sslmode=disable"),
		RabbitMQURL:    getEnv("RABBITMQ_URL", ""), // Empty default - RabbitMQ is optional
		JWTSecret:      getEnv("JWT_SECRET", "change-me-in-production"),
		SessionSecret:  getEnv("SESSION_SECRET", "change-me-in-production"),
		AppSecret:      getEnv("APP_SECRET", "32-byte-key-for-aes-encryption!"),
		AllowedOrigins: strings.Split(getEnv("ALLOWED_ORIGINS", "http://localhost:5173"), ","),
		SessionExpiry:  time.Duration(sessionExpiryHours) * time.Hour,
	}

	AppConfig = config
	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (c *Config) IsDevelopment() bool {
	return c.Env == "development"
}

func (c *Config) IsProduction() bool {
	return c.Env == "production"
}
