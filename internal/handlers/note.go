package handlers

import (
	"fmt"
	"strconv"
	"time"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

type NoteHandler struct {
	noteService *services.NoteService
}

func NewNoteHandler(noteService *services.NoteService) *NoteHandler {
	return &NoteHandler{
		noteService: noteService,
	}
}

// CreateNote handles POST /api/notes
func (h *NoteHandler) CreateNote(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var req struct {
		Title           string                 `json:"title"`
		Content         string                 `json:"content"`
		RemindAt        *string                `json:"remind_at"` // Expect ISO string
		IsReminder      bool                   `json:"is_reminder"`
		ReminderChannel models.ReminderChannel `json:"reminder_channel"`
		WebhookURL      *string                `json:"webhook_url"`
		WebhookPayload  *string                `json:"webhook_payload"`
		WhatsAppPhone   *string                `json:"whatsapp_phone"`
		BackgroundColor string                 `json:"background_color"`
		Tagline         string                 `json:"tagline"`
		RequestUUID     *uuid.UUID             `json:"request_uuid"`
	}

	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validation: Webhook URL required if channel is webhook
	if req.IsReminder && req.ReminderChannel == models.ReminderChannelWebhook {
		if req.WebhookURL == nil || *req.WebhookURL == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Webhook URL is required when choosing Webhook channel"})
		}
	}

	// Validation: WhatsApp phone required if channel is whatsapp
	if req.IsReminder && req.ReminderChannel == models.ReminderChannelWhatsApp {
		if req.WhatsAppPhone == nil || *req.WhatsAppPhone == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "WhatsApp phone number is required when choosing WhatsApp channel"})
		}
	}

	// Get user plan and check feature permissions
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("id = ?", userID).
		Scan(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch user"})
	}

	limits := models.GetPlanLimits(user.Plan)

	// Check reminder permission
	if req.IsReminder && !limits.Reminder {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Feature not available",
			"message": "Reminders are only available on Pro and Enterprise plans",
		})
	}

	// If note is attached to a request, check notes per request limit
	if req.RequestUUID != nil && limits.NotesPerRequest > 0 {
		notesCount, _ := database.DB.NewSelect().
			Model((*models.Note)(nil)).
			Where("request_uuid = ?", req.RequestUUID).
			Where("user_id = ?", userID).
			Count(c.Context())

		if notesCount >= limits.NotesPerRequest {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "Notes limit exceeded",
				"message": fmt.Sprintf("Your %s plan allows %d notes per request. Upgrade for more.", user.Plan, limits.NotesPerRequest),
			})
		}
	}

	note := &models.Note{
		UserID:          userID,
		Title:           req.Title,
		Content:         req.Content,
		IsReminder:      req.IsReminder,
		ReminderChannel: req.ReminderChannel,
		WebhookURL:      req.WebhookURL,
		WebhookPayload:  req.WebhookPayload,
		WhatsAppPhone:   req.WhatsAppPhone,
		BackgroundColor: req.BackgroundColor,
		Tagline:         req.Tagline,
		RequestUUID:     req.RequestUUID,
	}

	if req.RemindAt != nil && *req.RemindAt != "" {
		t, err := time.Parse(time.RFC3339, *req.RemindAt)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid remind_at format (use RFC3339)"})
		}
		note.RemindAt = &t
	}

	if err := h.noteService.CreateOrUpdateNote(c.Context(), note); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(note)
}

// UpdateNote handles PUT /api/notes/:id
func (h *NoteHandler) UpdateNote(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid UUID"})
	}

	var req struct {
		Title           string                 `json:"title"`
		Content         string                 `json:"content"`
		RemindAt        *string                `json:"remind_at"`
		IsReminder      bool                   `json:"is_reminder"`
		ReminderChannel models.ReminderChannel `json:"reminder_channel"`
		WebhookURL      *string                `json:"webhook_url"`
		WebhookPayload  *string                `json:"webhook_payload"`
		WhatsAppPhone   *string                `json:"whatsapp_phone"`
		BackgroundColor string                 `json:"background_color"`
		Tagline         string                 `json:"tagline"`
		RequestUUID     *uuid.UUID             `json:"request_uuid"`
	}

	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validation: Webhook URL required if channel is webhook
	if req.IsReminder && req.ReminderChannel == models.ReminderChannelWebhook {
		if req.WebhookURL == nil || *req.WebhookURL == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Webhook URL is required when choosing Webhook channel"})
		}
	}

	// Validation: WhatsApp phone required if channel is whatsapp
	if req.IsReminder && req.ReminderChannel == models.ReminderChannelWhatsApp {
		if req.WhatsAppPhone == nil || *req.WhatsAppPhone == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "WhatsApp phone number is required when choosing WhatsApp channel"})
		}
	}

	// Verify ownership first via GetNote (simple check)
	existing, err := h.noteService.GetNoteByID(c.Context(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Note not found"})
	}
	if existing.UserID != userID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Access denied"})
	}

	// Update fields
	existing.Title = req.Title
	existing.Content = req.Content
	existing.IsReminder = req.IsReminder
	existing.ReminderChannel = req.ReminderChannel
	existing.WebhookURL = req.WebhookURL
	existing.WebhookPayload = req.WebhookPayload
	existing.WhatsAppPhone = req.WhatsAppPhone
	existing.BackgroundColor = req.BackgroundColor
	existing.Tagline = req.Tagline
	existing.RequestUUID = req.RequestUUID

	if req.RemindAt != nil {
		if *req.RemindAt == "" {
			existing.RemindAt = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.RemindAt)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid remind_at format"})
			}
			existing.RemindAt = &t
		}
	}

	if err := h.noteService.CreateOrUpdateNote(c.Context(), existing); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(existing)
}

// GetNotes handles GET /api/notes
func (h *NoteHandler) GetNotes(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	filters := services.NoteFilters{
		UserID: userID,
		Limit:  10,
		Offset: 0,
	}

	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filters.Offset = (p - 1) * filters.Limit
		}
	}
	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			filters.Limit = l
		}
	}
	if search := c.Query("search"); search != "" {
		filters.Search = search
	}
	if date := c.Query("start_date"); date != "" {
		if t, err := time.Parse("2006-01-02", date); err == nil {
			filters.StartDate = &t
		}
	}
	if date := c.Query("end_date"); date != "" {
		if t, err := time.Parse("2006-01-02", date); err == nil {
			// Add 24h to include the end date fully
			t = t.Add(24 * time.Hour)
			filters.EndDate = &t
		}
	}
	if requestUUID := c.Query("request_uuid"); requestUUID != "" {
		if uid, err := uuid.Parse(requestUUID); err == nil {
			filters.RequestUUID = &uid
		}
	}

	notes, count, err := h.noteService.GetNotes(c.Context(), filters)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch notes"})
	}

	return c.JSON(fiber.Map{
		"notes": notes,
		"pagination": fiber.Map{
			"total": count,
			"page":  (filters.Offset / filters.Limit) + 1,
			"limit": filters.Limit,
		},
	})
}

// GetUpcomingReminders handles GET /api/notes/reminders
func (h *NoteHandler) GetUpcomingReminders(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	startStr := c.Query("start_date")
	endStr := c.Query("end_date")

	start := time.Now()
	end := time.Now().Add(7 * 24 * time.Hour) // Default next 7 days

	if startStr != "" {
		if t, err := time.Parse("2006-01-02", startStr); err == nil {
			start = t
		}
	}
	if endStr != "" {
		if t, err := time.Parse("2006-01-02", endStr); err == nil {
			end = t.Add(24 * time.Hour)
		}
	}

	notes, err := h.noteService.GetUpcomingReminders(c.Context(), userID, start, end)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch reminders"})
	}

	return c.JSON(notes)
}

// DeleteNote handles DELETE /api/notes/:id
func (h *NoteHandler) DeleteNote(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid UUID"})
	}

	if err := h.noteService.DeleteNote(c.Context(), id, userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete note"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}
