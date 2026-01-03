package handlers

import (
	"context"
	"strconv"

	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
)

type NotificationHandler struct {
	notificationService *services.NotificationService
}

func NewNotificationHandler(notificationService *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
	}
}

// List returns paginated notifications for the current user
func (h *NotificationHandler) List(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse pagination
	page := 1
	limit := 20
	if p, err := strconv.Atoi(c.Query("page", "1")); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(c.Query("limit", "20")); err == nil && l > 0 && l <= 50 {
		limit = l
	}
	offset := (page - 1) * limit

	ctx := context.Background()
	notifications, total, err := h.notificationService.GetUserNotifications(ctx, userID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch notifications",
		})
	}

	// Convert to response
	responses := make([]*models.NotificationResponse, len(notifications))
	for i := range notifications {
		responses[i] = notifications[i].ToResponse()
	}

	totalPages := total / limit
	if total%limit != 0 {
		totalPages++
	}

	return c.JSON(fiber.Map{
		"notifications": responses,
		"pagination": fiber.Map{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

// UnreadCount returns the count of unread notifications
func (h *NotificationHandler) UnreadCount(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()
	count, err := h.notificationService.GetUnreadCount(ctx, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch unread count",
		})
	}

	return c.JSON(fiber.Map{
		"count": count,
	})
}

// MarkAsRead marks a single notification as read
func (h *NotificationHandler) MarkAsRead(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	notificationID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid notification ID",
		})
	}

	ctx := context.Background()
	err = h.notificationService.MarkAsRead(ctx, notificationID, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to mark notification as read",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
	})
}

// MarkAllAsRead marks all notifications as read for the current user
func (h *NotificationHandler) MarkAllAsRead(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()
	err := h.notificationService.MarkAllAsRead(ctx, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to mark all notifications as read",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
	})
}
