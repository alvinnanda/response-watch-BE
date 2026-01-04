package handlers

import (
	"context"
	"strconv"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/gofiber/fiber/v3"
)

type VendorGroupHandler struct{}

func NewVendorGroupHandler() *VendorGroupHandler {
	return &VendorGroupHandler{}
}

// CreateVendorGroupPayload represents the create payload
type CreateVendorGroupPayload struct {
	GroupName   string       `json:"group_name"`
	VendorPhone string       `json:"vendor_phone"`
	PICs        []models.PIC `json:"pics"`      // New structure with name and phone
	PICNames    []string     `json:"pic_names"` // Deprecated, for backward compatibility
}

// Create handles creating a new vendor group
func (h *VendorGroupHandler) Create(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var payload CreateVendorGroupPayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	if payload.GroupName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Group name is required",
		})
	}

	ctx := context.Background()

	// Get user to check plan
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Column("id", "plan").
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to get user info",
		})
	}

	// Check vendor group limit based on plan
	planLimits := models.GetPlanLimits(user.Plan)
	if planLimits.VendorGroups > 0 {
		// Count existing vendor groups
		existingCount, err := database.DB.NewSelect().
			Model((*models.VendorGroup)(nil)).
			Where("user_id = ?", userID).
			Where("deleted_at IS NULL").
			Count(ctx)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to check vendor group count",
			})
		}

		if existingCount >= planLimits.VendorGroups {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "Limit Reached",
				"message": "You have reached the maximum number of vendor groups for your plan. Please upgrade to add more.",
				"limit":   planLimits.VendorGroups,
				"current": existingCount,
			})
		}
	}

	// Handle PICs - support both new and old format
	pics := payload.PICs
	if pics == nil {
		pics = []models.PIC{}
	}

	// Backward compatibility: if PICs is empty but PICNames has data, convert
	if len(pics) == 0 && len(payload.PICNames) > 0 {
		for _, name := range payload.PICNames {
			pics = append(pics, models.PIC{Name: name})
		}
	}

	vendorGroup := &models.VendorGroup{
		UserID:      userID,
		GroupName:   payload.GroupName,
		VendorPhone: payload.VendorPhone,
		PICs:        pics,
	}

	_, err = database.DB.NewInsert().Model(vendorGroup).Exec(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create vendor group",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(vendorGroup.ToResponse())
}

// List handles listing user's vendor groups
func (h *VendorGroupHandler) List(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Pagination
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if limit < 1 {
		limit = 10
	}
	offset := (page - 1) * limit

	ctx := context.Background()
	var groups []models.VendorGroup

	count, err := database.DB.NewSelect().
		Model(&groups).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		ScanAndCount(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch vendor groups",
		})
	}

	responses := make([]*models.VendorGroupResponse, len(groups))
	for i := range groups {
		responses[i] = groups[i].ToResponse()
	}

	totalPages := (count + limit - 1) / limit

	return c.JSON(fiber.Map{
		"vendor_groups": responses,
		"pagination": fiber.Map{
			"page":        page,
			"limit":       limit,
			"total":       count,
			"total_pages": totalPages,
		},
	})
}

// Get handles getting a single vendor group
func (h *VendorGroupHandler) Get(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	groupID := c.Params("id")

	ctx := context.Background()
	group := new(models.VendorGroup)

	err := database.DB.NewSelect().
		Model(group).
		Where("id = ?", groupID).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Vendor group not found",
		})
	}

	return c.JSON(group.ToResponse())
}

// Update handles updating a vendor group
func (h *VendorGroupHandler) Update(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	groupID := c.Params("id")

	var payload CreateVendorGroupPayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	ctx := context.Background()
	group := new(models.VendorGroup)

	err := database.DB.NewSelect().
		Model(group).
		Where("id = ?", groupID).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Vendor group not found",
		})
	}

	if payload.GroupName != "" {
		group.GroupName = payload.GroupName
	}
	if payload.VendorPhone != "" {
		group.VendorPhone = payload.VendorPhone
	}
	if payload.PICs != nil {
		group.PICs = payload.PICs
	} else if payload.PICNames != nil {
		// Backward compatibility: convert PICNames to PICs
		pics := []models.PIC{}
		for _, name := range payload.PICNames {
			pics = append(pics, models.PIC{Name: name})
		}
		group.PICs = pics
	}

	_, err = database.DB.NewUpdate().Model(group).WherePK().Exec(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update vendor group",
		})
	}

	return c.JSON(group.ToResponse())
}

// Delete handles deleting a vendor group
func (h *VendorGroupHandler) Delete(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	groupID := c.Params("id")
	ctx := context.Background()

	result, err := database.DB.NewDelete().
		Model((*models.VendorGroup)(nil)).
		Where("id = ?", groupID).
		Where("user_id = ?", userID).
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to delete vendor group",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Vendor group not found",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}
