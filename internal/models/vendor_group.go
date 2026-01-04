package models

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// PIC represents a Person In Charge with name and phone
type PIC struct {
	Name  string `json:"name"`
	Phone string `json:"phone,omitempty"`
}

type VendorGroup struct {
	bun.BaseModel `bun:"table:vendor_groups,alias:vg"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	UserID      int64  `bun:"user_id,notnull" json:"user_id"`
	User        *User  `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	GroupName   string `bun:"group_name,notnull" json:"group_name"`
	VendorPhone string `bun:"vendor_phone" json:"vendor_phone,omitempty"`
	PICs        []PIC  `bun:"pics,type:jsonb,default:'[]'" json:"pics"`
	// Deprecated: Use PICs instead. Kept for backward compatibility during migration.
	PICNames  []string   `bun:"pic_names,type:jsonb,default:'[]'" json:"pic_names,omitempty"`
	CreatedAt time.Time  `bun:"created_at,nullzero,default:now()" json:"created_at"`
	UpdatedAt time.Time  `bun:"updated_at,nullzero,default:now()" json:"updated_at"`
	DeletedAt *time.Time `bun:"deleted_at,soft_delete" json:"-"`
}

// VendorGroupResponse for API output
type VendorGroupResponse struct {
	ID          int64    `json:"id"`
	GroupName   string   `json:"group_name"`
	VendorPhone string   `json:"vendor_phone,omitempty"`
	PICs        []PIC    `json:"pics"`
	PICNames    []string `json:"pic_names"` // For backward compatibility
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func (vg *VendorGroup) ToResponse() *VendorGroupResponse {
	// Generate pic_names from PICs for backward compatibility
	picNames := make([]string, len(vg.PICs))
	for i, pic := range vg.PICs {
		picNames[i] = pic.Name
	}

	// If PICs is empty but PICNames has data (old data), use PICNames
	if len(vg.PICs) == 0 && len(vg.PICNames) > 0 {
		picNames = vg.PICNames
	}

	return &VendorGroupResponse{
		ID:          vg.ID,
		GroupName:   vg.GroupName,
		VendorPhone: vg.VendorPhone,
		PICs:        vg.PICs,
		PICNames:    picNames,
		CreatedAt:   vg.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   vg.UpdatedAt.Format(time.RFC3339),
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
