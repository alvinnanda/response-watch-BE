package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type ReminderChannel string

const (
	ReminderChannelEmail    ReminderChannel = "email"
	ReminderChannelWebhook  ReminderChannel = "webhook"
	ReminderChannelWhatsApp ReminderChannel = "whatsapp"
)

type Note struct {
	bun.BaseModel `bun:"table:notes,alias:n"`

	ID              uuid.UUID       `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	UserID          int64           `bun:"user_id,notnull" json:"user_id"`
	Title           string          `bun:"title,notnull" json:"title"`
	Content         string          `bun:"content,notnull" json:"content"`
	RemindAt        *time.Time      `bun:"remind_at" json:"remind_at,omitempty"`
	IsReminder      bool            `bun:"is_reminder" json:"is_reminder"`
	ReminderChannel ReminderChannel `bun:"reminder_channel,nullzero" json:"reminder_channel"`
	WebhookURL      *string         `bun:"webhook_url" json:"webhook_url,omitempty"`
	WebhookPayload  *string         `bun:"webhook_payload" json:"webhook_payload,omitempty"`
	WhatsAppPhone   *string         `bun:"whatsapp_phone" json:"whatsapp_phone,omitempty"`
	BackgroundColor string          `bun:"background_color" json:"background_color,omitempty"`
	Tagline         string          `bun:"tagline" json:"tagline,omitempty"`

	User        *User      `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	RequestUUID *uuid.UUID `bun:"request_uuid,type:uuid" json:"request_uuid,omitempty"`
	CreatedAt   time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt   time.Time  `bun:"updated_at,nullzero,default:now()" json:"updated_at"`
}

// BeforeInsert hook
var _ bun.BeforeInsertHook = (*Note)(nil)

func (n *Note) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	n.CreatedAt = time.Now()
	n.UpdatedAt = time.Now()
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook
var _ bun.BeforeUpdateHook = (*Note)(nil)

func (n *Note) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	n.UpdatedAt = time.Now()
	return nil
}
