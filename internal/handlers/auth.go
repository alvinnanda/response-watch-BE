package handlers

import (
	"context"
	"time"

	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
)

type AuthHandler struct {
	authService *services.AuthService
	jwtService  *services.JWTService
}

func NewAuthHandler(authService *services.AuthService, jwtService *services.JWTService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtService:  jwtService,
	}
}

// RegisterRequest represents the registration payload
type RegisterRequest struct {
	Email        string  `json:"email"`
	Password     string  `json:"password"`
	Username     string  `json:"username"`
	FullName     *string `json:"full_name,omitempty"`
	Organization *string `json:"organization,omitempty"`
}

// LoginRequest represents the login payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Register handles user registration
func (h *AuthHandler) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" || req.Username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Email, password, and username are required",
		})
	}

	// Validate username length
	if len(req.Username) < 3 || len(req.Username) > 10 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Username must be between 3 and 10 characters",
		})
	}

	// Validate password length
	if len(req.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Password must be at least 8 characters",
		})
	}

	ctx := context.Background()

	// Check if email already exists
	existingUser, _ := h.authService.GetUserByEmail(ctx, req.Email)
	if existingUser != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "Conflict",
			"message": "Email already registered",
		})
	}

	// Check if username already exists
	existingUsername, _ := h.authService.GetUserByUsername(ctx, req.Username)
	if existingUsername != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "Conflict",
			"message": "Username already taken",
		})
	}

	// Create user
	user, err := h.authService.CreateUser(ctx, req.Email, req.Password, req.Username, req.FullName, req.Organization)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create user",
		})
	}

	// Generate token
	token, err := h.authService.GenerateToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to generate token",
		})
	}

	// Set cookie
	h.setAuthCookie(c, token)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user":  user.ToResponse(),
		"token": token,
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Email and password are required",
		})
	}

	ctx := context.Background()

	// Get user by email
	user, err := h.authService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid email or password",
		})
	}

	// Check password
	if !h.authService.CheckPassword(req.Password, user.PasswordHash) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid email or password",
		})
	}

	// Check if user is active
	if !user.IsActive {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "Account is deactivated",
		})
	}

	// Update last login
	_ = h.authService.UpdateLastLogin(ctx, user.ID)

	// Generate token
	token, err := h.authService.GenerateToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to generate token",
		})
	}

	// Set cookie
	h.setAuthCookie(c, token)

	return c.JSON(fiber.Map{
		"user":  user.ToResponse(),
		"token": token,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	// Clear the auth cookie
	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   false, // Set to true in production
		SameSite: "Lax",
	})

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// Me returns the current user's information
func (h *AuthHandler) Me(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	ctx := context.Background()
	user, err := h.authService.GetUserByID(ctx, userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"user": user.ToResponse(),
	})
}

// UpdateProfileRequest represents the profile update payload
type UpdateProfileRequest struct {
	Username     *string `json:"username,omitempty"`
	FullName     *string `json:"full_name,omitempty"`
	Organization *string `json:"organization,omitempty"`
	IsPublic     *bool   `json:"is_public,omitempty"`
	NotifyEmail  *bool   `json:"notify_email,omitempty"`
}

// UpdateProfile updates the current user's profile
func (h *AuthHandler) UpdateProfile(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	var req UpdateProfileRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Validate username if provided
	if req.Username != nil {
		if len(*req.Username) < 3 || len(*req.Username) > 10 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Bad Request",
				"message": "Username must be between 3 and 10 characters",
			})
		}
	}

	ctx := context.Background()
	user, err := h.authService.UpdateProfile(ctx, userID, req.Username, req.FullName, req.Organization, req.IsPublic, req.NotifyEmail)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update profile",
		})
	}

	return c.JSON(fiber.Map{
		"user": user.ToResponse(),
	})
}

// setAuthCookie sets the authentication cookie
func (h *AuthHandler) setAuthCookie(c fiber.Ctx, token string) {
	expiry := h.jwtService.GetExpiry()
	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(expiry),
		HTTPOnly: true,
		Secure:   false, // Set to true in production
		SameSite: "Lax",
	})
}
