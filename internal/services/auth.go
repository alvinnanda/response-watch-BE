package services

import (
	"context"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	jwtService    *JWTService
	cryptoService *CryptoService
}

func NewAuthService(jwtService *JWTService, cryptoService *CryptoService) *AuthService {
	return &AuthService{
		jwtService:    jwtService,
		cryptoService: cryptoService,
	}
}

// HashPassword hashes a password using bcrypt
func (a *AuthService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func (a *AuthService) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CreateUser creates a new user with hashed password
func (a *AuthService) CreateUser(ctx context.Context, email, password, username string, fullName, organization *string) (*models.User, error) {
	hash, err := a.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:        email,
		PasswordHash: hash,
		Username:     username,
		FullName:     fullName,
		Organization: organization,
		IsActive:     true,
	}

	_, err = database.DB.NewInsert().Model(user).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (a *AuthService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("email = ?", email).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username (case-insensitive)
func (a *AuthService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("LOWER(username) = LOWER(?)", username).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByID retrieves a user by ID
func (a *AuthService) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateLastLogin updates the last_login_at timestamp
func (a *AuthService) UpdateLastLogin(ctx context.Context, userID int64) error {
	_, err := database.DB.NewUpdate().
		Model((*models.User)(nil)).
		Set("last_login_at = NOW()").
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// GenerateToken generates a JWT token for a user
func (a *AuthService) GenerateToken(user *models.User) (string, error) {
	return a.jwtService.GenerateToken(user.ID, user.Email, user.Username)
}

// ValidateToken validates a JWT token and returns claims
func (a *AuthService) ValidateToken(token string) (*JWTClaims, error) {
	return a.jwtService.ValidateToken(token)
}

// UpdateProfile updates user profile fields
func (a *AuthService) UpdateProfile(ctx context.Context, userID int64, username, fullName, organization *string, isPublic, notifyEmail *bool) (*models.User, error) {
	updateQuery := database.DB.NewUpdate().Model((*models.User)(nil)).Where("id = ?", userID)

	if username != nil {
		updateQuery = updateQuery.Set("username = ?", *username)
	}
	if fullName != nil {
		updateQuery = updateQuery.Set("full_name = ?", *fullName)
	}
	if organization != nil {
		updateQuery = updateQuery.Set("organization = ?", *organization)
	}
	if isPublic != nil {
		updateQuery = updateQuery.Set("is_public = ?", *isPublic)
	}
	if notifyEmail != nil {
		updateQuery = updateQuery.Set("notify_email = ?", *notifyEmail)
	}

	_, err := updateQuery.Exec(ctx)
	if err != nil {
		return nil, err
	}

	return a.GetUserByID(ctx, userID)
}
