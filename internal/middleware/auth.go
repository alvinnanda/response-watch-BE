package middleware

import (
	"strings"

	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
)

const (
	// ContextKeyUserID is the key for user ID in context
	ContextKeyUserID = "user_id"
	// ContextKeyUserEmail is the key for user email in context
	ContextKeyUserEmail = "user_email"
	// ContextKeyUsername is the key for username in context
	ContextKeyUsername = "username"
)

// AuthMiddleware creates a middleware that validates JWT tokens and session
func AuthMiddleware(jwtService *services.JWTService) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Try to get token from Authorization header first
		authHeader := c.Get("Authorization")
		var token string

		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}

		// If no token in header, try to get from cookie
		if token == "" {
			token = c.Cookies("token")
		}

		// If still no token, unauthorized
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
		}

		// Validate token
		claims, err := jwtService.ValidateToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": "Invalid or expired token",
			})
		}

		// Store user info in context
		c.Locals(ContextKeyUserID, claims.UserID)
		c.Locals(ContextKeyUserEmail, claims.Email)
		c.Locals(ContextKeyUsername, claims.Username)

		return c.Next()
	}
}

// OptionalAuthMiddleware tries to authenticate but doesn't require it
func OptionalAuthMiddleware(jwtService *services.JWTService) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		var token string

		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if token == "" {
			token = c.Cookies("token")
		}

		if token != "" {
			claims, err := jwtService.ValidateToken(token)
			if err == nil {
				c.Locals(ContextKeyUserID, claims.UserID)
				c.Locals(ContextKeyUserEmail, claims.Email)
				c.Locals(ContextKeyUsername, claims.Username)
			}
		}

		return c.Next()
	}
}

// GetUserID gets the user ID from context
func GetUserID(c fiber.Ctx) int64 {
	if id, ok := c.Locals(ContextKeyUserID).(int64); ok {
		return id
	}
	return 0
}

// GetUserEmail gets the user email from context
func GetUserEmail(c fiber.Ctx) string {
	if email, ok := c.Locals(ContextKeyUserEmail).(string); ok {
		return email
	}
	return ""
}

// GetUsername gets the username from context
func GetUsername(c fiber.Ctx) string {
	if username, ok := c.Locals(ContextKeyUsername).(string); ok {
		return username
	}
	return ""
}
