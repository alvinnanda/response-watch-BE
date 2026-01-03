package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/models"
)

type NotificationService struct {
	emailService *EmailService
}

func NewNotificationService(emailService *EmailService) *NotificationService {
	return &NotificationService{
		emailService: emailService,
	}
}

// CreateNotification creates a new in-app notification
func (s *NotificationService) CreateNotification(
	ctx context.Context,
	userID int64,
	requestID *int64,
	notifType string,
	title string,
	message string,
	metadata *models.NotificationMetadata,
) (*models.Notification, error) {
	// Marshal metadata
	metadataJSON, _ := json.Marshal(metadata)
	if metadata == nil {
		metadataJSON = []byte("{}")
	}

	notification := &models.Notification{
		UserID:    userID,
		RequestID: requestID,
		Type:      notifType,
		Title:     title,
		Message:   message,
		Metadata:  metadataJSON,
	}

	_, err := database.DB.NewInsert().Model(notification).Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create notification: %w", err)
	}

	return notification, nil
}

// NotifyStatusChange handles notification when request status changes
func (s *NotificationService) NotifyStatusChange(
	request *models.Request,
	requestTitle string,
	oldStatus string,
	newStatus string,
) error {
	ctx := context.Background()

	// Get request owner
	if request.UserID == nil {
		// Public request without owner, skip notification
		return nil
	}

	// Fetch user to get notification preferences
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("id = ?", *request.UserID).
		Scan(ctx)
	if err != nil {
		log.Printf("[NotificationService] Failed to fetch user %d: %v", *request.UserID, err)
		return err
	}

	// Generate notification content based on status change
	title, message := s.generateStatusChangeContent(requestTitle, oldStatus, newStatus, request)

	// Create metadata
	metadata := &models.NotificationMetadata{
		OldStatus:    oldStatus,
		NewStatus:    newStatus,
		RequestTitle: requestTitle,
		RequestToken: request.URLToken,
	}

	// 1. Always create in-app notification
	_, err = s.CreateNotification(ctx, user.ID, &request.ID, models.NotificationTypeStatusChange, title, message, metadata)
	if err != nil {
		log.Printf("[NotificationService] Failed to create in-app notification: %v", err)
	}

	// 2. Send email if user has enabled email notifications
	if user.NotifyEmail && s.emailService != nil {
		go s.sendEmailNotification(user.Email, title, message, request)
	}

	return nil
}

// generateStatusChangeContent creates title and message based on status change
func (s *NotificationService) generateStatusChangeContent(
	requestTitle string,
	oldStatus string,
	newStatus string,
	request *models.Request,
) (string, string) {
	var title, message string

	switch newStatus {
	case models.StatusInProgress:
		title = "Request Sedang Dikerjakan"
		picInfo := ""
		if request.StartPIC != nil && *request.StartPIC != "" {
			picInfo = fmt.Sprintf(" oleh %s", *request.StartPIC)
		}
		message = fmt.Sprintf("Request \"%s\" sedang dikerjakan%s.", requestTitle, picInfo)

	case models.StatusDone:
		title = "Request Selesai"
		picInfo := ""
		if request.EndPIC != nil && *request.EndPIC != "" {
			picInfo = fmt.Sprintf(" oleh %s", *request.EndPIC)
		}
		durationInfo := ""
		if request.DurationSeconds != nil {
			duration := time.Duration(*request.DurationSeconds) * time.Second
			durationInfo = fmt.Sprintf(" Durasi: %s.", formatDuration(duration))
		}
		message = fmt.Sprintf("Request \"%s\" telah selesai%s.%s", requestTitle, picInfo, durationInfo)

	default:
		title = "Status Request Berubah"
		message = fmt.Sprintf("Request \"%s\" berubah dari %s ke %s.", requestTitle, oldStatus, newStatus)
	}

	return title, message
}

// sendEmailNotification sends email notification asynchronously
func (s *NotificationService) sendEmailNotification(email, title, message string, request *models.Request) {
	// Build HTML body
	htmlBody := fmt.Sprintf(`
		<h2 style="color: #1f2937; margin-bottom: 16px;">%s</h2>
		<p style="color: #374151; font-size: 16px; margin-bottom: 24px;">%s</p>
		<p style="margin-top: 24px;">
			<a href="https://response-watch.web.app/t/%s" 
			   style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
				Lihat Request
			</a>
		</p>
	`, title, message, request.URLToken)

	subject := fmt.Sprintf("[ResponseWatch] %s", title)

	err := s.emailService.SendEmail([]string{email}, subject, htmlBody)
	if err != nil {
		log.Printf("[NotificationService] Failed to send email to %s: %v", email, err)
	} else {
		log.Printf("[NotificationService] Email sent to %s: %s", email, title)
	}
}

// GetUserNotifications returns notifications for a user
func (s *NotificationService) GetUserNotifications(ctx context.Context, userID int64, limit int, offset int) ([]models.Notification, int, error) {
	var notifications []models.Notification

	query := database.DB.NewSelect().
		Model(&notifications).
		Where("user_id = ?", userID).
		Order("created_at DESC")

	// Get total count
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Apply pagination
	err = query.Limit(limit).Offset(offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return notifications, total, nil
}

// GetUnreadCount returns the count of unread notifications
func (s *NotificationService) GetUnreadCount(ctx context.Context, userID int64) (int, error) {
	count, err := database.DB.NewSelect().
		Model((*models.Notification)(nil)).
		Where("user_id = ?", userID).
		Where("is_read = false").
		Count(ctx)
	return count, err
}

// MarkAsRead marks a notification as read
func (s *NotificationService) MarkAsRead(ctx context.Context, notificationID int64, userID int64) error {
	now := time.Now()
	_, err := database.DB.NewUpdate().
		Model((*models.Notification)(nil)).
		Set("is_read = true").
		Set("read_at = ?", now).
		Where("id = ?", notificationID).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

// MarkAllAsRead marks all notifications as read for a user
func (s *NotificationService) MarkAllAsRead(ctx context.Context, userID int64) error {
	now := time.Now()
	_, err := database.DB.NewUpdate().
		Model((*models.Notification)(nil)).
		Set("is_read = true").
		Set("read_at = ?", now).
		Where("user_id = ?", userID).
		Where("is_read = false").
		Exec(ctx)
	return err
}

// NotifyReminder creates an in-app notification when a reminder is triggered
func (s *NotificationService) NotifyReminder(
	userID int64,
	noteID string,
	noteTitle string,
	channel string,
	deliveryStatus string,
	deliveryError string,
) error {
	ctx := context.Background()

	// Use the note title as notification title (like a normal reminder)
	title := fmt.Sprintf("Pengingat: %s", noteTitle)

	// Generate message - simple and user-friendly
	var message string
	channelLabel := getChannelLabel(channel)

	if deliveryStatus == "sent" {
		message = fmt.Sprintf("Reminder ini telah dikirim ke %s.", channelLabel)
	} else {
		// Friendly error message without technical details
		message = fmt.Sprintf("Reminder ini tidak berhasil dikirim ke %s. Silakan cek pengaturan %s Anda.", channelLabel, channelLabel)
	}

	// Create metadata (keep technical details in metadata for debugging)
	metadata := &models.NotificationMetadata{
		NoteID:         noteID,
		NoteTitle:      noteTitle,
		Channel:        channel,
		DeliveryStatus: deliveryStatus,
		DeliveryError:  deliveryError,
	}

	_, err := s.CreateNotification(ctx, userID, nil, models.NotificationTypeReminder, title, message, metadata)
	if err != nil {
		log.Printf("[NotificationService] Failed to create reminder notification: %v", err)
		return err
	}

	log.Printf("[NotificationService] Reminder notification created for user %d: %s (%s)", userID, noteTitle, deliveryStatus)
	return nil
}

// getChannelLabel returns human-readable label for notification channel
func getChannelLabel(channel string) string {
	switch channel {
	case "email":
		return "Email"
	case "whatsapp":
		return "WhatsApp"
	case "webhook":
		return "Webhook"
	default:
		return channel
	}
}

// Helper function to format duration
func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	if h > 0 {
		return fmt.Sprintf("%dj %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
