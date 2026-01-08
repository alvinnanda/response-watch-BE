package models

import (
	"time"

	"github.com/uptrace/bun"
)

type DeviceUsage struct {
	bun.BaseModel `bun:"table:device_usage,alias:du"`

	ID              int64     `bun:"id,pk,autoincrement" json:"id"`
	FingerprintHash string    `bun:"fingerprint_hash,notnull" json:"fingerprint_hash"`
	Action          string    `bun:"action,notnull,default:'create_request'" json:"action"`
	IPAddress       *string   `bun:"ip_address" json:"ip_address,omitempty"`
	RealIP          *string   `bun:"real_ip" json:"real_ip,omitempty"`
	UserAgent       *string   `bun:"user_agent" json:"user_agent,omitempty"`
	CreatedAt       time.Time `bun:"created_at,nullzero,default:now()" json:"created_at"`
}

// Action constants
const (
	ActionCreateRequest = "create_request"
	ActionVerifyPinFail = "verify_pin_fail"
)
