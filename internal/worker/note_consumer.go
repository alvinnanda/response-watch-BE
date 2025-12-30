package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/rabbitmq"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type NoteWorker struct {
	noteService     *services.NoteService
	emailService    *services.EmailService
	whatsappService *services.WhatsAppService
}

func NewNoteWorker(ns *services.NoteService, es *services.EmailService, ws *services.WhatsAppService) *NoteWorker {
	return &NoteWorker{
		noteService:     ns,
		emailService:    es,
		whatsappService: ws,
	}
}

// StartWorker starts the consumer process
// ctx is used for graceful shutdown signal
func (w *NoteWorker) StartWorker(ctx context.Context) error {
	if rabbitmq.Client == nil {
		return fmt.Errorf("RabbitMQ client not initialized")
	}

	ch := rabbitmq.Client.Channel
	qName := rabbitmq.ProcessingQueueName

	msgs, err := ch.Consume(
		qName,           // queue
		"note-worker-1", // consumer tag
		false,           // auto-ack (FALSE because we want manual ack after successful process)
		false,           // exclusive
		false,           // no-local
		false,           // no-wait
		nil,             // args
	)
	if err != nil {
		return fmt.Errorf("failed to register consumer: %w", err)
	}

	fmt.Printf(" [*] Worker started. Waiting for messages in %s. To exit press CTRL+C\n", qName)

	// Goroutine to handle messages
	done := make(chan bool)

	go func() {
		for d := range msgs {
			w.processMessage(ctx, d)
		}
		done <- true
	}()

	// Wait for context cancellation (Graceful Shutdown)
	<-ctx.Done()
	fmt.Println(" [x] Shutdown signal received. Canceling consumer...")

	// Cancel the consumer to stop receiving new messages
	if err := ch.Cancel("note-worker-1", false); err != nil {
		fmt.Printf("Error canceling consumer: %v\n", err)
	}

	// Wait for the message processing loop to finish (channel closed by server after cancel usually, or we wait for current jobs)
	// Note: amqp channel close will close the msgs channel.
	// But strictly, Cancel just stops delivery. We might need to wait for last job.
	// For simplicity in this demo:
	fmt.Println(" [x] Worker exiting")
	return nil
}

func (w *NoteWorker) processMessage(ctx context.Context, d amqp.Delivery) {
	noteIDStr := string(d.Body)
	log.Printf(" [x] Received reminder for Note ID: %s", noteIDStr)

	// 1. Parsing ID
	noteID, err := uuid.Parse(noteIDStr)
	if err != nil {
		log.Printf(" [!] Invalid UUID format: %s. Rejecting.", noteIDStr)
		d.Reject(false) // Dead letter again? No, just discard if invalid
		return
	}

	// 2. Fetch Latest Data (DB Query - Late Binding)
	note, err := w.noteService.GetNoteByID(ctx, noteID)
	if err != nil {
		log.Printf(" [!] Note not found (maybe deleted): %s. Acknowledging to remove from queue.", noteID)
		d.Ack(false)
		return
	}

	// 3. Validation Logic
	// a. Check if reminder is still active
	if !note.IsReminder {
		log.Printf(" [i] Note %s: Reminder disabled by user. Skipping.", note.ID)
		d.Ack(false)
		return
	}

	// b. Check if remidner time is valid (prevent race conditions or old messages)
	// Allow a small grace period (e.g. processed within 5 mins of scheduled time? or just "is it passed?")
	// Actually, if it's in the queue, it's passed. Logic is: Is it TOO late? or did user update it to Future again?
	// If user updated `remind_at` to future, this message (from old schedule) should be ignored if it doesn't match current `remind_at`.
	// Simple check: Diff < small_threshold? OR strictly: timestamp in DB < Now + threshold?
	// A better check for "User changed mind and rescheduled":
	// The message only has ID. We don't know the ORIGINAL scheduled time of THIS message.
	// Ideal payload includes "ScheduledFor" timestamp to compare.
	// BUT req says "Payload: Hanya kirim note_id".
	// So we assume if `remind_at` is in the past (since it's a reminder for "now" or "past"), it's valid to send for general Logic.
	// If user Rescheduled to Next Year, `remind_at` in DB will be > Now.
	// So: If Note.RemindAt > Now + 1 minute, it means it was rescheduled. Ignore this old ping.
	if note.RemindAt != nil && note.RemindAt.After(time.Now().Add(1*time.Minute)) {
		log.Printf(" [i] Note %s: Reminder appears to be rescheduled to %v. Skipping old trigger.", note.ID, note.RemindAt)
		d.Ack(false)
		return
	}

	// 4. Execute (Simulate Sending)
	w.sendNotification(note)

	// 5. Ack
	d.Ack(false)
}

func (w *NoteWorker) sendNotification(note *models.Note) {
	msg := fmt.Sprintf("REMINDER for Note '%s': %s", note.Title, note.Content)

	switch note.ReminderChannel {
	case models.ReminderChannelWebhook:
		w.sendWebhook(note)
	case models.ReminderChannelEmail:
		if note.User == nil || note.User.Email == "" {
			log.Printf(" [!] Cannot send email: User email not found for note %s", note.ID)
			// Still ack? Yes, otherwise it loops forever.
			return
		}

		subject := fmt.Sprintf("Reminder: %s", note.Title)
		// Basic HTML Template
		body := fmt.Sprintf(`<h2 style="margin-top: 0; color: #111827;">%s</h2>
<p style="margin-bottom: 24px; line-height: 1.6;">%s</p>`, note.Title, note.Content)

		if note.Tagline != "" {
			body += fmt.Sprintf(`<p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-style: italic; font-size: 14px;">%s</p>`, note.Tagline)
		}

		err := w.emailService.SendEmail([]string{note.User.Email}, subject, body)
		if err != nil {
			log.Printf(" [!] Failed to send email to %s: %v", note.User.Email, err)
		} else {
			fmt.Printf(" >>> [EMAIL SENT] To %s: %s\n", note.User.Email, note.Title)
		}
	case models.ReminderChannelWhatsApp:
		if note.WhatsAppPhone == nil || *note.WhatsAppPhone == "" {
			log.Printf(" [!] Cannot send WhatsApp: Phone number not set for note %s", note.ID)
			return
		}

		// Helper regex to strip HTML tags
		re := regexp.MustCompile(`<[^>]*>`)
		cleanContent := re.ReplaceAllString(note.Content, "")
		cleanContent = strings.TrimSpace(cleanContent)

		// Format message for WhatsApp
		waMessage := fmt.Sprintf("*%s*\n\n%s", note.Title, cleanContent)
		if note.Tagline != "" {
			waMessage += fmt.Sprintf("\n\n_%s_", note.Tagline)
		}

		// Add footer with organization if available
		if note.User != nil && note.User.Organization != nil && *note.User.Organization != "" {
			waMessage += fmt.Sprintf("\n\n— %s via ResponseWatch", *note.User.Organization)
		} else {
			waMessage += "\n\n— ResponseWatch Reminder"
		}

		err := w.whatsappService.SendMessage(*note.WhatsAppPhone, waMessage)
		if err != nil {
			log.Printf(" [!] Failed to send WhatsApp to %s: %v", *note.WhatsAppPhone, err)
		} else {
			fmt.Printf(" >>> [WHATSAPP SENT] To %s: %s\n", *note.WhatsAppPhone, note.Title)
		}
	default:
		fmt.Printf(" >>> [DEFAULT NOTIF] %s\n", msg)
	}
}

func (w *NoteWorker) sendWebhook(note *models.Note) {
	if note.WebhookURL == nil || *note.WebhookURL == "" {
		log.Printf(" [!] Webhook URL is empty for note %s", note.ID)
		return
	}

	url := *note.WebhookURL
	var payload []byte

	// Use custom payload if provided
	if note.WebhookPayload != nil && *note.WebhookPayload != "" {
		// Template substitution
		customBody := *note.WebhookPayload
		customBody = strings.ReplaceAll(customBody, "{{title}}", note.Title)
		customBody = strings.ReplaceAll(customBody, "{{content}}", note.Content)
		// Try to see if it's valid JSON, if not send as string in a default wrapper?
		// Actually, let's assume user provides JSON. if checks fail, maybe wrap it?
		// For simplicity, we just send as is (assuming Application/JSON)
		payload = []byte(customBody)
	} else {
		// Default Payload
		defaultBody := map[string]string{
			"message": fmt.Sprintf("Reminder: %s", note.Title),
			"content": note.Content,
			"note_id": note.ID.String(),
		}
		jsonBody, _ := json.Marshal(defaultBody)
		payload = jsonBody
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf(" [!] Failed to create webhook request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ResponseWatch-Event", "reminder")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf(" [!] Webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf(" >>> [WEBHOOK SUCCEEDED] %s (Status: %d)\n", url, resp.StatusCode)
	} else {
		log.Printf(" [!] Webhook failed with status: %d", resp.StatusCode)
	}
}
