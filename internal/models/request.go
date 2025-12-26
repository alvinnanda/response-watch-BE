package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type Request struct {
	bun.BaseModel `bun:"table:requests,alias:r"`

	ID   int64     `bun:"id,pk,autoincrement" json:"id"`
	UUID uuid.UUID `bun:"uuid,notnull,unique,default:gen_random_uuid()" json:"uuid"`

	// Ownership
	UserID *int64 `bun:"user_id" json:"user_id"`
	User   *User  `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`

	// Public access token
	URLToken string `bun:"url_token,notnull,unique" json:"url_token"`

	// Encrypted content (stored encrypted, decrypted on read)
	TitleEncrypted        string  `bun:"title_encrypted,notnull" json:"-"`
	DescriptionEncrypted  *string `bun:"description_encrypted" json:"-"`
	FollowupLinkEncrypted *string `bun:"followup_link" json:"-"`

	// Decrypted fields (not stored in DB, populated by service)
	Title        string  `bun:"-" json:"title"`
	Description  *string `bun:"-" json:"description,omitempty"`
	FollowupLink *string `bun:"-" json:"followup_link,omitempty"`

	// State
	Status string `bun:"status,default:'waiting'" json:"status"`

	// PIC logic
	EmbeddedPICList []string `bun:"embedded_pic_list,type:jsonb,default:'[]'" json:"embedded_pic_list"`

	// Execution data
	StartPIC *string `bun:"start_pic" json:"start_pic,omitempty"`
	EndPIC   *string `bun:"end_pic" json:"end_pic,omitempty"`

	// Audit trail
	StartIP   *string `bun:"start_ip" json:"start_ip,omitempty"`
	EndIP     *string `bun:"end_ip" json:"end_ip,omitempty"`
	UserAgent *string `bun:"user_agent" json:"user_agent,omitempty"`

	// Timing metrics
	CreatedAt  time.Time  `bun:"created_at,nullzero,default:now()" json:"created_at"`
	UpdatedAt  time.Time  `bun:"updated_at,nullzero,default:now()" json:"updated_at"`
	StartedAt  *time.Time `bun:"started_at" json:"started_at,omitempty"`
	FinishedAt *time.Time `bun:"finished_at" json:"finished_at,omitempty"`

	// Calculated fields
	DurationSeconds     *int `bun:"duration_seconds" json:"duration_seconds,omitempty"`
	ResponseTimeSeconds *int `bun:"response_time_seconds" json:"response_time_seconds,omitempty"`

	// Soft delete
	DeletedAt *time.Time `bun:"deleted_at,soft_delete" json:"-"`

	// Joined fields
	PICIsPublic *bool `bun:"pic_is_public,scanonly" json:"pic_is_public,omitempty"`
}

// Request statuses
const (
	StatusWaiting    = "waiting"
	StatusInProgress = "in_progress"
	StatusDone       = "done"
)

// RequestResponse for API output
type RequestResponse struct {
	ID                  int64    `json:"id"`
	UUID                string   `json:"uuid"`
	URLToken            string   `json:"url_token"`
	Title               string   `json:"title"`
	Description         *string  `json:"description,omitempty"`
	FollowupLink        *string  `json:"followup_link,omitempty"`
	Status              string   `json:"status"`
	EmbeddedPICList     []string `json:"embedded_pic_list"`
	StartPIC            *string  `json:"start_pic,omitempty"`
	EndPIC              *string  `json:"end_pic,omitempty"`
	StartIP             *string  `json:"start_ip,omitempty"`
	EndIP               *string  `json:"end_ip,omitempty"`
	CreatedAt           string   `json:"created_at"`
	StartedAt           *string  `json:"started_at,omitempty"`
	FinishedAt          *string  `json:"finished_at,omitempty"`
	DurationSeconds     *int     `json:"duration_seconds,omitempty"`
	ResponseTimeSeconds *int     `json:"response_time_seconds,omitempty"`
	PICIsPublic         *bool    `json:"pic_is_public,omitempty"`
}

func (r *Request) ToResponse() *RequestResponse {
	resp := &RequestResponse{
		ID:                  r.ID,
		UUID:                r.UUID.String(),
		URLToken:            r.URLToken,
		Title:               r.Title,
		Description:         r.Description,
		FollowupLink:        r.FollowupLink,
		Status:              r.Status,
		EmbeddedPICList:     r.EmbeddedPICList,
		StartPIC:            r.StartPIC,
		EndPIC:              r.EndPIC,
		StartIP:             r.StartIP,
		EndIP:               r.EndIP,
		CreatedAt:           r.CreatedAt.Format(time.RFC3339),
		DurationSeconds:     r.DurationSeconds,
		ResponseTimeSeconds: r.ResponseTimeSeconds,
		PICIsPublic:         r.PICIsPublic,
	}

	if r.StartedAt != nil {
		s := r.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &s
	}
	if r.FinishedAt != nil {
		f := r.FinishedAt.Format(time.RFC3339)
		resp.FinishedAt = &f
	}

	return resp
}

// BeforeInsert hook
var _ bun.BeforeInsertHook = (*Request)(nil)

func (r *Request) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	r.CreatedAt = time.Now()
	r.UpdatedAt = time.Now()
	if r.UUID == uuid.Nil {
		r.UUID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook
var _ bun.BeforeUpdateHook = (*Request)(nil)

func (r *Request) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	r.UpdatedAt = time.Now()
	return nil
}
