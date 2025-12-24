package middleware

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
)

// RateLimitMiddleware creates an IP-based rate limiter
// Limits: 10 requests per minute per IP
func RateLimitMiddleware() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        15,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c fiber.Ctx) string {
			// Use X-Real-IP if available (behind nginx), otherwise use client IP
			return GetRealIP(c)
		},
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":       "Too many requests",
				"message":     "Please slow down. Try again in a minute.",
				"retry_after": 60,
			})
		},
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: false,
	})
}

// GetRealIP extracts the real client IP from headers or connection
// Priority: X-Real-IP > X-Forwarded-For > c.IP()
func GetRealIP(c fiber.Ctx) string {
	// Check X-Real-IP first (set by nginx)
	if realIP := c.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Check X-Forwarded-For (may contain multiple IPs)
	if forwardedFor := c.Get("X-Forwarded-For"); forwardedFor != "" {
		// Return the first IP in the list
		return forwardedFor
	}

	// Fallback to connection IP
	return c.IP()
}
