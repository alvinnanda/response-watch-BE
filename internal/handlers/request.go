package handlers

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
)

type RequestHandler struct {
	cryptoService *services.CryptoService
}

func NewRequestHandler(cryptoService *services.CryptoService) *RequestHandler {
	return &RequestHandler{
		cryptoService: cryptoService,
	}
}

// CreateRequestPayload represents the create request payload
type CreateRequestPayload struct {
	Title           string   `json:"title"`
	Description     *string  `json:"description,omitempty"`
	FollowupLink    *string  `json:"followup_link,omitempty"`
	EmbeddedPICList []string `json:"embedded_pic_list,omitempty"`
}

// Create handles creating a new request
func (h *RequestHandler) Create(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var payload CreateRequestPayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	if payload.Title == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Title is required",
		})
	}

	// Encrypt title and description
	titleEncrypted, err := h.cryptoService.Encrypt(payload.Title)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	descEncrypted, err := h.cryptoService.EncryptPtr(payload.Description)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	followupEncrypted, err := h.cryptoService.EncryptPtr(payload.FollowupLink)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	// Generate URL token with retry logic for collision handling
	ctx := context.Background()
	var urlToken string
	const maxRetries = 3

	for i := 0; i < maxRetries; i++ {
		urlToken = generateURLToken(8)

		// Check if token already exists
		exists, _ := database.DB.NewSelect().
			Model((*models.Request)(nil)).
			Where("url_token = ?", urlToken).
			Exists(ctx)

		if !exists {
			break
		}

		if i == maxRetries-1 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to generate unique token, please try again",
			})
		}
	}

	picList := payload.EmbeddedPICList
	if picList == nil {
		picList = []string{}
	}

	request := &models.Request{
		UserID:                userID,
		URLToken:              urlToken,
		TitleEncrypted:        titleEncrypted,
		DescriptionEncrypted:  descEncrypted,
		FollowupLinkEncrypted: followupEncrypted,
		Status:                models.StatusWaiting,
		EmbeddedPICList:       picList,
	}

	_, err = database.DB.NewInsert().Model(request).Exec(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create request",
		})
	}

	// Decrypt for response
	request.Title = payload.Title
	request.Description = payload.Description
	request.FollowupLink = payload.FollowupLink

	return c.Status(fiber.StatusCreated).JSON(request.ToResponse())
}

// PublicCreatePayload for public request creation
type PublicCreatePayload struct {
	Title        string  `json:"title"`
	Description  *string `json:"description,omitempty"`
	FollowupLink *string `json:"followup_link,omitempty"`
	Fingerprint  string  `json:"fingerprint"`
}

// CreatePublic handles creating a request without authentication
// Rate limited by device fingerprint (10/month)
func (h *RequestHandler) CreatePublic(c fiber.Ctx) error {
	var payload PublicCreatePayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	if payload.Title == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Title is required",
		})
	}

	if payload.Fingerprint == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Device fingerprint is required",
		})
	}

	// Hash the fingerprint
	hash := sha256.Sum256([]byte(payload.Fingerprint))
	fingerprintHash := hex.EncodeToString(hash[:])

	ctx := context.Background()

	// Get real IP for rate limit check
	realIP := middleware.GetRealIP(c)

	// Check monthly usage limit (10 per month)
	// Single query: check fingerprint OR IP to prevent manipulation
	const monthlyLimit = 10
	startOfMonth := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -time.Now().Day()+1)

	usageCount, _ := database.DB.NewSelect().
		Model((*models.DeviceUsage)(nil)).
		Where("(fingerprint_hash = ? OR real_ip = ?)", fingerprintHash, realIP).
		Where("action = ?", models.ActionCreateRequest).
		Where("created_at >= ?", startOfMonth).
		Count(ctx)

	if usageCount >= monthlyLimit {
		// Calculate next month reset
		nextMonth := startOfMonth.AddDate(0, 1, 0)
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":           "Monthly limit exceeded",
			"message":         "You've used 10/10 free requests this month. Login for unlimited access.",
			"remaining_quota": 0,
			"reset_at":        nextMonth.Format(time.RFC3339),
		})
	}

	// Encrypt title and description
	titleEncrypted, err := h.cryptoService.Encrypt(payload.Title)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	descEncrypted, err := h.cryptoService.EncryptPtr(payload.Description)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	followupEncrypted, err := h.cryptoService.EncryptPtr(payload.FollowupLink)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to encrypt data",
		})
	}

	// Generate URL token with retry
	var urlToken string
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		urlToken = generateURLToken(8)
		exists, _ := database.DB.NewSelect().
			Model((*models.Request)(nil)).
			Where("url_token = ?", urlToken).
			Exists(ctx)
		if !exists {
			break
		}
		if i == maxRetries-1 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to generate unique token",
			})
		}
	}

	// Get client info for logging
	clientIP := c.IP()
	userAgent := c.Get("User-Agent")

	// Create request (user_id = 0 for public requests)
	request := &models.Request{
		UserID:                0, // No user for public requests
		URLToken:              urlToken,
		TitleEncrypted:        titleEncrypted,
		DescriptionEncrypted:  descEncrypted,
		FollowupLinkEncrypted: followupEncrypted,
		Status:                models.StatusWaiting,
		EmbeddedPICList:       []string{},
	}

	_, err = database.DB.NewInsert().Model(request).Exec(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create request",
		})
	}

	// Log device usage
	deviceUsage := &models.DeviceUsage{
		FingerprintHash: fingerprintHash,
		Action:          models.ActionCreateRequest,
		IPAddress:       &clientIP,
		RealIP:          &realIP,
		UserAgent:       &userAgent,
	}
	database.DB.NewInsert().Model(deviceUsage).Exec(ctx)

	// Decrypt for response
	request.Title = payload.Title
	request.Description = payload.Description
	request.FollowupLink = payload.FollowupLink

	// Return with remaining quota
	remainingQuota := monthlyLimit - usageCount - 1

	response := request.ToResponse()
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"request":         response,
		"remaining_quota": remainingQuota,
	})
}

// List handles listing user's requests with pagination and filters
func (h *RequestHandler) List(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse pagination params
	page := 1
	limit := 10
	if p, err := strconv.Atoi(c.Query("page", "1")); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(c.Query("limit", "10")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}
	offset := (page - 1) * limit

	// Parse filter params
	status := c.Query("status")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	search := c.Query("search")

	ctx := context.Background()
	var requests []models.Request

	// Build query
	query := database.DB.NewSelect().
		Model(&requests).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	// Apply filters
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if startDate != "" {
		query = query.Where("created_at >= ?", startDate)
	}
	if endDate != "" {
		query = query.Where("created_at <= ?::date + INTERVAL '1 day'", endDate)
	}
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("(start_pic ILIKE ? OR end_pic ILIKE ?)", searchPattern, searchPattern)
	}

	// Get total count first
	total, err := query.Count(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to count requests",
		})
	}

	// Apply pagination and fetch
	err = query.Limit(limit).Offset(offset).Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch requests",
		})
	}

	// Decrypt each request
	for i := range requests {
		requests[i].Title, _ = h.cryptoService.Decrypt(requests[i].TitleEncrypted)
		requests[i].Description, _ = h.cryptoService.DecryptPtr(requests[i].DescriptionEncrypted)
		requests[i].FollowupLink, _ = h.cryptoService.DecryptPtr(requests[i].FollowupLinkEncrypted)
	}

	responses := make([]*models.RequestResponse, len(requests))
	for i := range requests {
		responses[i] = requests[i].ToResponse()
	}

	// Calculate total pages
	totalPages := total / limit
	if total%limit != 0 {
		totalPages++
	}

	return c.JSON(fiber.Map{
		"requests": responses,
		"pagination": fiber.Map{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

// Stats returns request statistics for the current user
func (h *RequestHandler) Stats(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()

	// Get counts by status
	var stats []struct {
		Status string `bun:"status"`
		Count  int    `bun:"count"`
	}

	err := database.DB.NewSelect().
		TableExpr("requests").
		Column("status").
		ColumnExpr("COUNT(*) AS count").
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Group("status").
		Scan(ctx, &stats)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch stats",
		})
	}

	// Build response
	result := fiber.Map{
		"waiting":     0,
		"in_progress": 0,
		"done":        0,
		"total":       0,
	}

	total := 0
	for _, s := range stats {
		result[s.Status] = s.Count
		total += s.Count
	}
	result["total"] = total

	return c.JSON(result)
}

// Get handles getting a single request by ID
func (h *RequestHandler) Get(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	requestID := c.Params("id")

	ctx := context.Background()
	request := new(models.Request)

	err := database.DB.NewSelect().
		Model(request).
		Where("id = ?", requestID).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	// Decrypt
	request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)
	request.FollowupLink, _ = h.cryptoService.DecryptPtr(request.FollowupLinkEncrypted)

	return c.JSON(request.ToResponse())
}

// Update handles updating a request
func (h *RequestHandler) Update(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	requestID := c.Params("id")

	var payload CreateRequestPayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	ctx := context.Background()

	// Check ownership
	request := new(models.Request)
	err := database.DB.NewSelect().
		Model(request).
		Where("id = ?", requestID).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Scan(ctx)

	// Encrypt new values
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	if request.Status == models.StatusDone {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "Cannot update a completed request",
		})
	}
	if payload.Title != "" {
		titleEncrypted, err := h.cryptoService.Encrypt(payload.Title)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to encrypt data",
			})
		}
		request.TitleEncrypted = titleEncrypted
		request.Title = payload.Title
	}

	if payload.Description != nil {
		descEncrypted, err := h.cryptoService.EncryptPtr(payload.Description)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to encrypt data",
			})
		}
		request.DescriptionEncrypted = descEncrypted
		request.Description = payload.Description
	}

	if payload.FollowupLink != nil {
		followupEncrypted, err := h.cryptoService.EncryptPtr(payload.FollowupLink)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to encrypt data",
			})
		}
		request.FollowupLinkEncrypted = followupEncrypted
		request.FollowupLink = payload.FollowupLink
	}

	if payload.EmbeddedPICList != nil {
		request.EmbeddedPICList = payload.EmbeddedPICList
	}

	_, err = database.DB.NewUpdate().
		Model(request).
		WherePK().
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update request",
		})
	}

	return c.JSON(request.ToResponse())
}

// Delete handles soft deleting a request
func (h *RequestHandler) Delete(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	requestID := c.Params("id")
	ctx := context.Background()

	result, err := database.DB.NewDelete().
		Model((*models.Request)(nil)).
		Where("id = ?", requestID).
		Where("user_id = ?", userID).
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to delete request",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// GetByToken handles getting a request by URL token (public)
func (h *RequestHandler) GetByToken(c fiber.Ctx) error {
	token := c.Params("token")

	ctx := context.Background()
	request := new(models.Request)

	err := database.DB.NewSelect().
		Model(request).
		Where("url_token = ?", token).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	// Decrypt
	request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)
	request.FollowupLink, _ = h.cryptoService.DecryptPtr(request.FollowupLinkEncrypted)

	return c.JSON(request.ToResponse())
}

// StartResponsePayload for starting response
type StartResponsePayload struct {
	PICName string `json:"pic_name,omitempty"`
}

// StartResponse handles the vendor starting response
func (h *RequestHandler) StartResponse(c fiber.Ctx) error {
	token := c.Params("token")

	var payload StartResponsePayload
	_ = c.Bind().JSON(&payload) // Optional payload

	ctx := context.Background()
	request := new(models.Request)

	err := database.DB.NewSelect().
		Model(request).
		Where("url_token = ?", token).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	if request.Status != models.StatusWaiting {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Request is not in waiting status",
		})
	}

	now := time.Now()
	clientIP := c.IP()
	userAgent := c.Get("User-Agent")

	// Calculate response time
	responseTimeSeconds := int(now.Sub(request.CreatedAt).Seconds())

	// Update request
	_, err = database.DB.NewUpdate().
		Model((*models.Request)(nil)).
		Set("status = ?", models.StatusInProgress).
		Set("started_at = ?", now).
		Set("start_ip = ?", clientIP).
		Set("start_pic = ?", payload.PICName).
		Set("user_agent = ?", userAgent).
		Set("response_time_seconds = ?", responseTimeSeconds).
		Where("id = ?", request.ID).
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to start response",
		})
	}

	// Reload and return
	database.DB.NewSelect().Model(request).Where("id = ?", request.ID).Scan(ctx)
	request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)

	return c.JSON(request.ToResponse())
}

// FinishResponsePayload for finishing response
type FinishResponsePayload struct {
	PICName string `json:"pic_name,omitempty"`
}

// FinishResponse handles the vendor finishing response
func (h *RequestHandler) FinishResponse(c fiber.Ctx) error {
	token := c.Params("token")

	var payload FinishResponsePayload
	_ = c.Bind().JSON(&payload)

	ctx := context.Background()
	request := new(models.Request)

	err := database.DB.NewSelect().
		Model(request).
		Where("url_token = ?", token).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	if request.Status != models.StatusInProgress {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Request is not in progress",
		})
	}

	now := time.Now()
	clientIP := c.IP()

	// Calculate duration
	var durationSeconds int
	if request.StartedAt != nil {
		durationSeconds = int(now.Sub(*request.StartedAt).Seconds())
	}

	// Use start PIC if no end PIC provided
	endPIC := payload.PICName
	if endPIC == "" && request.StartPIC != nil {
		endPIC = *request.StartPIC
	}

	// Update request
	_, err = database.DB.NewUpdate().
		Model((*models.Request)(nil)).
		Set("status = ?", models.StatusDone).
		Set("finished_at = ?", now).
		Set("end_ip = ?", clientIP).
		Set("end_pic = ?", endPIC).
		Set("duration_seconds = ?", durationSeconds).
		Where("id = ?", request.ID).
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to finish response",
		})
	}

	// Reload and return
	database.DB.NewSelect().Model(request).Where("id = ?", request.ID).Scan(ctx)
	request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)

	return c.JSON(request.ToResponse())
}

// GetPublicRequestsByUsername handles getting requests by username (public monitoring)
func (h *RequestHandler) GetPublicRequestsByUsername(c fiber.Ctx) error {
	username := c.Params("username")

	ctx := context.Background()

	// 1. Find User
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("username = ?", username).
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "User not found",
		})
	}

	// 2. Parse Pagination
	page := 1
	limit := 10
	if p, err := strconv.Atoi(c.Query("page", "1")); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(c.Query("limit", "10")); err == nil && l > 0 && l <= 50 {
		limit = l
	}
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	// 3. Parse Filters
	status := c.Query("status")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Enforce 90-day limit
	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)
	today := time.Now()

	// Parse and validate start_date
	var startDate time.Time
	if startDateStr != "" {
		parsed, err := time.Parse("2006-01-02", startDateStr)
		if err == nil {
			// Clamp to 90 days ago if older
			if parsed.Before(ninetyDaysAgo) {
				startDate = ninetyDaysAgo
			} else {
				startDate = parsed
			}
		} else {
			// Invalid format, default to today
			startDate = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())
		}
	} else {
		// No start_date provided, default to today (not 90 days ago)
		startDate = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())
	}

	// Parse and validate end_date (default to today)
	var endDate time.Time
	if endDateStr != "" {
		parsed, err := time.Parse("2006-01-02", endDateStr)
		if err == nil {
			// Don't allow future dates
			if parsed.After(today) {
				endDate = today
			} else {
				endDate = parsed.Add(24 * time.Hour) // Include the full day
			}
		} else {
			endDate = today.Add(24 * time.Hour)
		}
	} else {
		endDate = today.Add(24 * time.Hour)
	}

	// 4. Build Query with Constraints
	var requests []models.Request
	query := database.DB.NewSelect().
		Model(&requests).
		ColumnExpr("r.*").
		ColumnExpr("u.is_public AS pic_is_public").
		Join("LEFT JOIN users AS u ON r.user_id = u.id").
		Where("r.user_id = ?", user.ID).
		Where("r.deleted_at IS NULL").
		Where("u.is_public = true").
		Where("r.created_at >= ?", startDate).
		Where("r.created_at < ?", endDate).
		Order("r.created_at DESC")

	if status != "" {
		query = query.Where("r.status = ?", status)
	}

	// 5. Execute Count & Select
	total, err := query.Count(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to count requests",
		})
	}

	err = query.Limit(limit).Offset(offset).Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch requests",
		})
	}

	// 6. Decrypt info (Title/Desc only) - Keep secure link private?
	// The requirement is public monitoring. Usually titles are safe.
	for i := range requests {
		requests[i].Title, _ = h.cryptoService.Decrypt(requests[i].TitleEncrypted)
		requests[i].Description, _ = h.cryptoService.DecryptPtr(requests[i].DescriptionEncrypted)
		// Hide edit/followup links for public view?
		// For now, let's just decrypt them. The frontend can choose what to show.
		// Actually, followup link might be sensitive if it's a private meeting link.
		// But the "Smart Link" page itself is public via token.
		// Let's decrypt common fields.
		requests[i].FollowupLink, _ = h.cryptoService.DecryptPtr(requests[i].FollowupLinkEncrypted)
	}

	responses := make([]*models.RequestResponse, len(requests))
	for i := range requests {
		responses[i] = requests[i].ToResponse()
	}

	totalPages := total / limit
	if total%limit != 0 {
		totalPages++
	}

	return c.JSON(fiber.Map{
		"requests": responses,
		"pagination": fiber.Map{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
		"user": fiber.Map{
			"username":     user.Username,
			"full_name":    user.FullName,
			"organization": user.Organization,
		},
	})
}

// generateURLToken generates a cryptographically secure random URL-safe token
func generateURLToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := cryptorand.Read(b); err != nil {
		// Fallback: this should never happen in practice
		return ""
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
