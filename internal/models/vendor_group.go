package models

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

type VendorGroup struct {
	bun.BaseModel `bun:"table:vendor_groups,alias:vg"`

	ID        int64      `bun:"id,pk,autoincrement" json:"id"`
	UserID    int64      `bun:"user_id,notnull" json:"user_id"`
	User      *User      `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	GroupName string     `bun:"group_name,notnull" json:"group_name"`
	PICNames  []string   `bun:"pic_names,type:jsonb,default:'[]'" json:"pic_names"`
	CreatedAt time.Time  `bun:"created_at,nullzero,default:now()" json:"created_at"`
	UpdatedAt time.Time  `bun:"updated_at,nullzero,default:now()" json:"updated_at"`
	DeletedAt *time.Time `bun:"deleted_at,soft_delete" json:"-"`
}

// VendorGroupResponse for API output
type VendorGroupResponse struct {
	ID        int64    `json:"id"`
	GroupName string   `json:"group_name"`
	PICNames  []string `json:"pic_names"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

func (vg *VendorGroup) ToResponse() *VendorGroupResponse {
	return &VendorGroupResponse{
		ID:        vg.ID,
		GroupName: vg.GroupName,
		PICNames:  vg.PICNames,
		CreatedAt: vg.CreatedAt.Format(time.RFC3339),
		UpdatedAt: vg.UpdatedAt.Format(time.RFC3339),
	}
}

// BeforeInsert hook
var _ bun.BeforeInsertHook = (*VendorGroup)(nil)

func (vg *VendorGroup) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	vg.CreatedAt = time.Now()
	vg.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook
var _ bun.BeforeUpdateHook = (*VendorGroup)(nil)

func (vg *VendorGroup) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	vg.UpdatedAt = time.Now()
	return nil
}
