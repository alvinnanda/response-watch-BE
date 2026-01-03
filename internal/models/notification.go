package models

import (
	"context"
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// NotificationType constants
const (
	NotificationTypeStatusChange   = "status_change"
	NotificationTypeRequestCreated = "request_created"
	NotificationTypeReminder       = "reminder"
)

// NotificationMetadata for storing extra information
type NotificationMetadata struct {
	// Status change fields
	OldStatus    string `json:"old_status,omitempty"`
	NewStatus    string `json:"new_status,omitempty"`
	RequestTitle string `json:"request_title,omitempty"`
	RequestToken string `json:"request_token,omitempty"`

	// Reminder fields
	NoteID         string `json:"note_id,omitempty"`
	NoteTitle      string `json:"note_title,omitempty"`
	Channel        string `json:"channel,omitempty"`         // email, whatsapp, webhook
	DeliveryStatus string `json:"delivery_status,omitempty"` // sent, failed
	DeliveryError  string `json:"delivery_error,omitempty"`
}

type Notification struct {
	bun.BaseModel `bun:"table:notifications,alias:n"`

	ID        int64  `bun:"id,pk,autoincrement" json:"id"`
	UserID    int64  `bun:"user_id,notnull" json:"user_id"`
	RequestID *int64 `bun:"request_id" json:"request_id,omitempty"`

	Type    string `bun:"type,notnull" json:"type"`
	Title   string `bun:"title,notnull" json:"title"`
	Message string `bun:"message,notnull" json:"message"`

	IsRead bool       `bun:"is_read,default:false" json:"is_read"`
	ReadAt *time.Time `bun:"read_at" json:"read_at,omitempty"`

	Metadata  json.RawMessage `bun:"metadata,type:jsonb,default:'{}'" json:"metadata"`
	CreatedAt time.Time       `bun:"created_at,nullzero,default:now()" json:"created_at"`
}

// NotificationResponse for API output
type NotificationResponse struct {
	ID        int64                `json:"id"`
	UserID    int64                `json:"user_id"`
	RequestID *int64               `json:"request_id,omitempty"`
	Type      string               `json:"type"`
	Title     string               `json:"title"`
	Message   string               `json:"message"`
	IsRead    bool                 `json:"is_read"`
	ReadAt    *string              `json:"read_at,omitempty"`
	Metadata  NotificationMetadata `json:"metadata"`
	CreatedAt string               `json:"created_at"`
}

func (n *Notification) ToResponse() *NotificationResponse {
	resp := &NotificationResponse{
		ID:        n.ID,
		UserID:    n.UserID,
		RequestID: n.RequestID,
		Type:      n.Type,
		Title:     n.Title,
		Message:   n.Message,
		IsRead:    n.IsRead,
		CreatedAt: n.CreatedAt.Format(time.RFC3339),
	}

	if n.ReadAt != nil {
		r := n.ReadAt.Format(time.RFC3339)
		resp.ReadAt = &r
	}

	// Parse metadata
	if len(n.Metadata) > 0 {
		json.Unmarshal(n.Metadata, &resp.Metadata)
	}

	return resp
}

// BeforeInsert hook
var _ bun.BeforeInsertHook = (*Notification)(nil)

func (n *Notification) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	n.CreatedAt = time.Now()
	return nil
}
