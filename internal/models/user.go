package models

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID              int64      `bun:"id,pk,autoincrement" json:"id"`
	Username        string     `bun:"username,notnull,unique" json:"username"`
	Email           string     `bun:"email,notnull,unique" json:"email"`
	PasswordHash    string     `bun:"password_hash,notnull" json:"-"`
	FullName        *string    `bun:"full_name" json:"full_name,omitempty"`
	Organization    *string    `bun:"organization" json:"organization,omitempty"`
	IsActive        bool       `bun:"is_active,default:true" json:"is_active"`
	IsPublic        bool       `bun:"is_public,default:false" json:"is_public"`
	EmailVerified   bool       `bun:"email_verified,default:false" json:"email_verified"`
	EmailVerifiedAt *time.Time `bun:"email_verified_at" json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `bun:"created_at,nullzero,default:now()" json:"created_at"`
	UpdatedAt       time.Time  `bun:"updated_at,nullzero,default:now()" json:"updated_at"`
	LastLoginAt     *time.Time `bun:"last_login_at" json:"last_login_at,omitempty"`
	DeletedAt       *time.Time `bun:"deleted_at,soft_delete" json:"-"`

	// Subscription
	Plan                  string     `bun:"plan,default:'free'" json:"plan"`
	MonthlyRequestCount   int        `bun:"monthly_request_count,default:0" json:"-"`
	RequestCountResetAt   time.Time  `bun:"request_count_reset_at,default:now()" json:"-"`
	SubscriptionExpiresAt *time.Time `bun:"subscription_expires_at" json:"-"`

	// Notification Preferences
	NotifyEmail bool `bun:"notify_email,default:false" json:"notify_email"`
}

// UserResponse is the safe representation for API responses
type UserResponse struct {
	ID            int64   `json:"id"`
	Username      string  `json:"username"`
	Email         string  `json:"email"`
	FullName      *string `json:"full_name,omitempty"`
	Organization  *string `json:"organization,omitempty"`
	IsActive      bool    `json:"is_active"`
	IsPublic      bool    `json:"is_public"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"` // For frontend compatibility
	Plan          string  `json:"plan"`
	NotifyEmail   bool    `json:"notify_email"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		FullName:      u.FullName,
		Organization:  u.Organization,
		IsActive:      u.IsActive,
		IsPublic:      u.IsPublic,
		EmailVerified: u.EmailVerified,
		Role:          "user", // Default role
		Plan:          u.Plan,
		NotifyEmail:   u.NotifyEmail,
		CreatedAt:     u.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     u.UpdatedAt.Format(time.RFC3339),
	}
}

// BeforeInsert hook
var _ bun.BeforeInsertHook = (*User)(nil)

func (u *User) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook
var _ bun.BeforeUpdateHook = (*User)(nil)

func (u *User) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	u.UpdatedAt = time.Now()
	return nil
}

// CheckAndDowngrade checks if subscription expired and downgrades to free
func (u *User) CheckAndDowngrade() bool {
	// If user has paid plan and subscription expired, downgrade to free
	if u.Plan != PlanFree && u.SubscriptionExpiresAt != nil {
		if time.Now().After(*u.SubscriptionExpiresAt) {
			u.Plan = PlanFree
			u.SubscriptionExpiresAt = nil
			return true // Indicates plan was downgraded
		}
	}
	return false
}
