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
	GroupName string   `json:"group_name"`
	PICNames  []string `json:"pic_names"`
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

	picNames := payload.PICNames
	if picNames == nil {
		picNames = []string{}
	}

	vendorGroup := &models.VendorGroup{
		UserID:    userID,
		GroupName: payload.GroupName,
		PICNames:  picNames,
	}

	ctx := context.Background()
	_, err := database.DB.NewInsert().Model(vendorGroup).Exec(ctx)
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
	if payload.PICNames != nil {
		group.PICNames = payload.PICNames
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
