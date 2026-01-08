package services

import (
	"context"
	"fmt"
	"time"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/rabbitmq"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type NoteService struct{}

func NewNoteService() *NoteService {
	return &NoteService{}
}

// NoteFilters defines available filters for listing notes
type NoteFilters struct {
	UserID      int64
	StartDate   *time.Time
	EndDate     *time.Time
	Search      string
	Limit       int
	Offset      int
	RequestUUID *uuid.UUID
}

// CreateOrUpdateNote saves the note and schedules a reminder if needed
func (s *NoteService) CreateOrUpdateNote(ctx context.Context, note *models.Note) error {
	// 1. Save to Database (Upsert logic or just Insert for simplicity as per requirement "CreateOrUpdate")
	// Using Upsert for "CreateOrUpdate" semantics if ID is provided
	var err error
	if note.ID == uuid.Nil {
		note.ID = uuid.New()
	}

	// Upsert: On conflict update
	_, err = database.DB.NewInsert().
		Model(note).
		On("CONFLICT (id) DO UPDATE").
		Set("title = EXCLUDED.title").
		Set("content = EXCLUDED.content").
		Set("remind_at = EXCLUDED.remind_at").
		Set("is_reminder = EXCLUDED.is_reminder").
		Set("reminder_channel = EXCLUDED.reminder_channel").
		Set("webhook_url = EXCLUDED.webhook_url").
		Set("webhook_payload = EXCLUDED.webhook_payload").
		Set("whatsapp_phone = EXCLUDED.whatsapp_phone").
		Set("background_color = EXCLUDED.background_color").
		Set("tagline = EXCLUDED.tagline").
		Set("request_uuid = EXCLUDED.request_uuid").
		Set("updated_at = ?", time.Now()).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to save note: %w", err)
	}

	// 2. Schedule Reminder if applicable
	// NOTE: If updating, we might schedule a DUPLICATE reminder message.
	// In the worker, we check `RemindAt` vs. Now. If it was rescheduled, the old message will be ignored
	// because its "trigger time" (implicitly Now) will be valid, but if we assume the worker checks
	// if "RemindAt" is close to Now...
	// Actually, the worker check I implemented was: `if note.RemindAt.After(Now + 1m) { skip }`.
	// This handles rescheduling to the future. So publishing a new message is fine.
	if note.IsReminder && note.RemindAt != nil {
		now := time.Now()
		delay := note.RemindAt.Sub(now)

		if delay > 0 {
			// Publish to RabbitMQ Waiting Queue
			err = rabbitmq.PublishScheduleNote(note.ID.String(), *note.RemindAt, delay)
			if err != nil {
				return fmt.Errorf("note saved but failed to safe reminder: %w", err)
			}
		} else {
			// If time is already passed, maybe trigger immediately or ignore?
			fmt.Println("Warning: RemindAt is in the past, skipping scheduler")
		}
	}

	return nil
}

// GetNoteByID executes Step 3a: Query DB for latest data
func (s *NoteService) GetNoteByID(ctx context.Context, id uuid.UUID) (*models.Note, error) {
	note := new(models.Note)
	err := database.DB.NewSelect().
		Model(note).
		Relation("User").
		Where("n.id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return note, nil
}

// GetNotes retrieves a list of notes based on filters
func (s *NoteService) GetNotes(ctx context.Context, filters NoteFilters) ([]models.Note, int, error) {
	var notes []models.Note
	query := database.DB.NewSelect().
		Model(&notes).
		Where("n.user_id = ?", filters.UserID).
		Relation("Request").
		Order("n.created_at DESC") // Default sort

	if filters.RequestUUID != nil {
		query.Where("n.request_uuid = ?", filters.RequestUUID)
	}
	if filters.StartDate != nil {
		query.Where("n.created_at >= ?", filters.StartDate)
	}
	if filters.EndDate != nil {
		query.Where("n.created_at <= ?", filters.EndDate)
	}
	if filters.Search != "" {
		query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("n.title ILIKE ?", "%"+filters.Search+"%").
				WhereOr("n.content ILIKE ?", "%"+filters.Search+"%")
		})
	}

	// Also support filtering by RemindAt range if needed (e.g. for Dashboard "Upcoming Reminders")
	// For simplicity, let's say if Start/End provided, we check BOTH created OR remind_at?
	// The requirement is "jika ada reminder yang akan di jadwalkan dalam range filter dashboard tampilkan".
	// So we might need a separate query for reminders specifically, or just include them.
	// Let's stick to standard filtering for now, and maybe add a specialized "GetUpcomingReminders" method or rely on the client to ask.
	// Actually, let's assume the filters apply to `created_at` for the main list.
	// But the user said: "if there are reminders scheduled within the range filter... display them".
	// So maybe we modify the query to be: (created_at OR remind_at) in range?
	// Let's implement a separate GetUpcomingReminders for clarity.

	if filters.Limit > 0 {
		query.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		query.Offset(filters.Offset)
	}

	// Execute query
	count, err := query.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, err
	}

	return notes, count, nil
}

// GetUpcomingReminders retrieves notes with reminders in the specified range
func (s *NoteService) GetUpcomingReminders(ctx context.Context, userID int64, start, end time.Time) ([]models.Note, error) {
	var notes []models.Note
	err := database.DB.NewSelect().
		Model(&notes).
		Where("user_id = ?", userID).
		Where("is_reminder = TRUE").
		Where("remind_at >= ?", start).
		Where("remind_at <= ?", end).
		Order("remind_at ASC").
		Scan(ctx)

	if err != nil {
		fmt.Printf("GetUpcomingReminders Error: %v\n", err)
		return nil, err
	}
	return notes, nil
}

func (s *NoteService) DeleteNote(ctx context.Context, id uuid.UUID, userID int64) error {
	_, err := database.DB.NewDelete().
		Model((*models.Note)(nil)).
		Where("id = ?", id).
		Where("user_id = ?", userID). // Security: ensure user owns note
		Exec(ctx)
	return err
}
