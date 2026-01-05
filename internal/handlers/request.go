package handlers

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/models"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
)

type RequestHandler struct {
	cryptoService       *services.CryptoService
	notificationService *services.NotificationService
}

func NewRequestHandler(cryptoService *services.CryptoService, notificationService *services.NotificationService) *RequestHandler {
	return &RequestHandler{
		cryptoService:       cryptoService,
		notificationService: notificationService,
	}
}

// CreateRequestPayload represents the create request payload
type CreateRequestPayload struct {
	Title               string   `json:"title"`
	Description         *string  `json:"description,omitempty"`
	FollowupLink        *string  `json:"followup_link,omitempty"`
	EmbeddedPICList     []string `json:"embedded_pic_list,omitempty"`
	IsDescriptionSecure bool     `json:"is_description_secure"`
	DescriptionPIN      *string  `json:"description_pin,omitempty"`
	VendorGroupID       *int64   `json:"vendor_group_id,omitempty"`
	ScheduledTime       *string  `json:"scheduled_time,omitempty"`
}

// Create handles creating a new request
func (h *RequestHandler) Create(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()

	// Get user and check plan limits
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch user",
		})
	}

	// Check and auto-downgrade if subscription expired
	wasDowngraded := user.CheckAndDowngrade()

	// Check if monthly reset needed (automatic monthly reset)
	if time.Now().After(user.RequestCountResetAt) {
		user.MonthlyRequestCount = 0
		user.RequestCountResetAt = time.Now().AddDate(0, 1, 0) // Next month
		wasDowngraded = true                                   // Force update
	}

	// Save user if plan changed or monthly reset occurred
	if wasDowngraded {
		database.DB.NewUpdate().Model(user).WherePK().Exec(ctx)
	}

	// Check plan limits
	limits := models.GetPlanLimits(user.Plan)
	if limits.MonthlyRequests > 0 && user.MonthlyRequestCount >= limits.MonthlyRequests {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":        "Monthly limit exceeded",
			"message":      fmt.Sprintf("You've reached your %s plan limit (%d requests/month). Upgrade to continue.", user.Plan, limits.MonthlyRequests),
			"current_plan": user.Plan,
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

	// Check secure description permission
	if payload.IsDescriptionSecure && !limits.SecureDesc {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Feature not available",
			"message": "Secure description is only available on Pro and Enterprise plans",
		})
	}

	// Title is now stored as plain text for search (no encryption)
	// Encrypt description only
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

	// Hash PIN if secure description is enabled
	var pinHash *string
	if payload.IsDescriptionSecure && payload.DescriptionPIN != nil && *payload.DescriptionPIN != "" {
		hash := sha256.Sum256([]byte(*payload.DescriptionPIN))
		hashStr := hex.EncodeToString(hash[:])
		pinHash = &hashStr
	}

	// Parse scheduled time if present
	var scheduledTime *time.Time
	if payload.ScheduledTime != nil && *payload.ScheduledTime != "" {
		t, err := time.Parse(time.RFC3339, *payload.ScheduledTime)
		if err == nil {
			scheduledTime = &t
		}
	}

	request := &models.Request{
		UserID:                &userID,
		Title:                 payload.Title, // Plain text title
		DescriptionEncrypted:  descEncrypted,
		FollowupLinkEncrypted: followupEncrypted,
		VendorGroupID:         payload.VendorGroupID,
		URLToken:              urlToken,
		Status:                models.StatusWaiting,
		EmbeddedPICList:       picList,
		IsDescriptionSecure:   payload.IsDescriptionSecure,
		DescriptionPINHash:    pinHash,
		ScheduledTime:         scheduledTime,
	}

	_, err = database.DB.NewInsert().Model(request).Exec(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create request",
		})
	}

	// Decrypt description and followup for response (title is already plain)
	request.Description = payload.Description
	request.FollowupLink = payload.FollowupLink

	// Increment request count
	user.MonthlyRequestCount++
	database.DB.NewUpdate().Model(user).WherePK().Exec(ctx)

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

	// Create request (user_id = nil for public requests)
	request := &models.Request{
		UserID:                nil, // No user for public requests
		URLToken:              urlToken,
		TitleEncrypted:        titleEncrypted,
		DescriptionEncrypted:  descEncrypted,
		FollowupLinkEncrypted: followupEncrypted,
		Status:                models.StatusWaiting,
		EmbeddedPICList:       []string{},
	}

	_, err = database.DB.NewInsert().Model(request).Exec(ctx)
	if err != nil {
		log.Printf("[CreatePublic] Failed to insert request: %v", err)
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

// CreatePublicForUser handles creating a request for a specific user without authentication
// Rate limited by device fingerprint (10/month)
func (h *RequestHandler) CreatePublicForUser(c fiber.Ctx) error {
	username := c.Params("username")
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Username is required",
		})
	}

	ctx := context.Background()

	// 1. Find User by username
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("username = ?", username).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "User not found",
		})
	}

	// 2. Check if user is public
	if !user.IsPublic {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "This user does not accept public requests",
		})
	}

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
			"details": err.Error(),
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

	// Create request (assigned to user.ID)
	request := &models.Request{
		UserID:                &user.ID, // Assigned to the specific user
		URLToken:              urlToken,
		TitleEncrypted:        titleEncrypted,
		DescriptionEncrypted:  descEncrypted,
		FollowupLinkEncrypted: followupEncrypted,
		Status:                models.StatusWaiting,
		EmbeddedPICList:       []string{},
	}

	_, err = database.DB.NewInsert().Model(request).Exec(ctx)
	if err != nil {
		log.Printf("[CreatePublicForUser] Failed to insert request: %v", err)
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
	vendorGroupIDStr := c.Query("vendor_group_id")

	ctx := context.Background()

	// Get user plan for history limits
	user := new(models.User)
	err := database.DB.NewSelect().
		Model(user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch user",
		})
	}

	limits := models.GetPlanLimits(user.Plan)

	var requests []models.Request

	// Build query with vendor group relation
	query := database.DB.NewSelect().
		Model(&requests).
		Relation("VendorGroup").
		Where("r.user_id = ?", userID).
		Where("r.deleted_at IS NULL").
		Order("r.created_at DESC")

	// Apply history retention based on plan
	if limits.HistoryDays > 0 {
		cutoffDate := time.Now().AddDate(0, 0, -limits.HistoryDays)
		query = query.Where("r.created_at >= ?", cutoffDate)
	}

	// Apply filters
	if status != "" {
		query = query.Where("r.status = ?", status)
	}
	if startDate != "" {
		query = query.Where("r.created_at >= ?", startDate)
	}
	if endDate != "" {
		query = query.Where("r.created_at <= ?::date + INTERVAL '1 day'", endDate)
	}
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("(r.title ILIKE ? OR r.start_pic ILIKE ? OR r.end_pic ILIKE ?)", searchPattern, searchPattern, searchPattern)
	}
	if vendorGroupIDStr != "" {
		if vendorGroupID, err := strconv.ParseInt(vendorGroupIDStr, 10, 64); err == nil {
			query = query.Where("r.vendor_group_id = ?", vendorGroupID)
		}
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

	// Decrypt/fallback for each request
	for i := range requests {
		// Title: use plain text if available, otherwise decrypt from encrypted (backward compat)
		if requests[i].Title == "" && requests[i].TitleEncrypted != "" {
			requests[i].Title, _ = h.cryptoService.Decrypt(requests[i].TitleEncrypted)
		}
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

// Stats returns basic request statistics for the current user
func (h *RequestHandler) Stats(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()

	// Parse filters (only needed for basic counts if we want them filtered, usually basic counts are filtered too)
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	vendorGroupID, _ := strconv.Atoi(c.Query("vendor_group_id"))
	search := c.Query("search")

	// Helper to apply filters
	applyFilters := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("r.user_id = ?", userID).
			Where("r.deleted_at IS NULL")

		if startDate != "" {
			q = q.Where("r.created_at >= ?::timestamp", startDate+" 00:00:00")
		}
		if endDate != "" {
			q = q.Where("r.created_at <= ?::timestamp", endDate+" 23:59:59")
		}
		if vendorGroupID > 0 {
			q = q.Where("r.vendor_group_id = ?", vendorGroupID)
		}
		if search != "" {
			q = q.WhereGroup(" AND ", func(g *bun.SelectQuery) *bun.SelectQuery {
				return g.Where("r.title ILIKE ?", "%"+search+"%").
					WhereOr("r.start_pic ILIKE ?", "%"+search+"%").
					WhereOr("r.end_pic ILIKE ?", "%"+search+"%")
			})
		}
		return q
	}

	// 1. Get counts by status
	var stats []struct {
		Status string `bun:"status"`
		Count  int    `bun:"count"`
	}

	q1 := database.DB.NewSelect().
		TableExpr("requests AS r").
		Column("r.status").
		ColumnExpr("COUNT(*) AS count").
		Group("r.status")

	err := applyFilters(q1).Scan(ctx, &stats)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch stats",
		})
	}

	total := 0
	result := fiber.Map{
		"waiting":     0,
		"in_progress": 0,
		"done":        0,
		"total":       0,
	}

	for _, s := range stats {
		result[s.Status] = s.Count
		total += s.Count
	}
	result["total"] = total

	return c.JSON(result)
}

// StatsPremium returns advanced request statistics for the current user
func (h *RequestHandler) StatsPremium(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Check if user is allowed to access premium stats?
	// For now we trust the frontend to gate it, but good practice to check logic or just serve it since they might have valid access
	// The requirement is to save query power for free users.
	// We can check the user plan here if we want to enforce it at API level.

	ctx := context.Background()

	// Parse filters
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	vendorGroupID, _ := strconv.Atoi(c.Query("vendor_group_id"))
	search := c.Query("search")

	// Default to last 7 days if not provided
	if startDate == "" {
		startDate = time.Now().AddDate(0, 0, -6).Format("2006-01-02")
	}
	if endDate == "" {
		endDate = time.Now().Format("2006-01-02")
	}

	// Helper to apply filters
	applyFilters := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("r.user_id = ?", userID).
			Where("r.deleted_at IS NULL")

		if startDate != "" {
			q = q.Where("r.created_at >= ?::timestamp", startDate+" 00:00:00")
		}
		if endDate != "" {
			q = q.Where("r.created_at <= ?::timestamp", endDate+" 23:59:59")
		}
		if vendorGroupID > 0 {
			q = q.Where("r.vendor_group_id = ?", vendorGroupID)
		}
		if search != "" {
			q = q.WhereGroup(" AND ", func(g *bun.SelectQuery) *bun.SelectQuery {
				return g.Where("r.title ILIKE ?", "%"+search+"%").
					WhereOr("r.start_pic ILIKE ?", "%"+search+"%").
					WhereOr("r.end_pic ILIKE ?", "%"+search+"%")
			})
		}
		return q
	}

	// 2. Get average times (Global) & Extra Stats
	var timeStats struct {
		AvgResponseMinutes   float64 `bun:"avg_response"`
		AvgCompletionMinutes float64 `bun:"avg_completion"`
		ScheduledCount       int     `bun:"scheduled_count"`
		ReopenCount          int     `bun:"reopen_count"`
	}

	q2 := database.DB.NewSelect().
		TableExpr("requests AS r").
		ColumnExpr("COALESCE(AVG(r.response_time_seconds) / 60, 0) AS avg_response").
		ColumnExpr("COALESCE(AVG(r.duration_seconds) / 60, 0) AS avg_completion").
		ColumnExpr("COUNT(*) FILTER (WHERE r.status = 'waiting' AND r.scheduled_time > NOW()) AS scheduled_count").
		ColumnExpr("COALESCE(SUM(r.reopen_count), 0) AS reopen_count")

	err := applyFilters(q2).Scan(ctx, &timeStats)

	// 3. Get Daily Trends with generate_series
	var dailyStats []struct {
		Date  string `bun:"date" json:"date"`
		Count int    `bun:"count" json:"count"`
	}

	// Construct WHERE clause for the requests part
	whereClause := "r.user_id = ? AND r.deleted_at IS NULL"
	args := []interface{}{userID}

	if startDate != "" {
		whereClause += " AND r.created_at >= ?::timestamp"
		args = append(args, startDate+" 00:00:00")
	}
	if endDate != "" {
		whereClause += " AND r.created_at <= ?::timestamp"
		args = append(args, endDate+" 23:59:59")
	}
	if vendorGroupID > 0 {
		whereClause += " AND r.vendor_group_id = ?"
		args = append(args, vendorGroupID)
	}
	if search != "" {
		whereClause += " AND (r.title ILIKE ? OR r.start_pic ILIKE ? OR r.end_pic ILIKE ?)"
		like := "%" + search + "%"
		args = append(args, like, like, like)
	}

	rawQuery := `
		WITH dates AS (
			SELECT to_char(date_trunc('day', d)::date, 'YYYY-MM-DD') as date
			FROM generate_series(
				?::date,
				?::date,
				'1 day'::interval
			) d
		)
		SELECT 
			d.date,
			COUNT(r.id) as count
		FROM dates d
		LEFT JOIN requests r ON to_char(r.created_at, 'YYYY-MM-DD') = d.date 
			AND ` + whereClause + `
		GROUP BY d.date
		ORDER BY d.date ASC
	`
	// Prepend start/end date for generate_series to args
	finalArgs := append([]interface{}{startDate, endDate}, args...)

	err = database.DB.NewRaw(rawQuery, finalArgs...).Scan(ctx, &dailyStats)

	// 4. Get Vendor Stats
	var vendorStats []struct {
		VendorName           string  `bun:"vendor_name" json:"vendor_name"`
		Total                int     `bun:"total" json:"total"`
		AvgResponseMinutes   float64 `bun:"avg_response" json:"avg_response_time_minutes"`
		AvgCompletionMinutes float64 `bun:"avg_completion" json:"avg_completion_time_minutes"`
		TotalReopen          int     `bun:"total_reopen" json:"total_reopen"`
	}

	q4 := database.DB.NewSelect().
		TableExpr("requests AS r").
		ColumnExpr("vg.group_name AS vendor_name").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("COALESCE(AVG(r.response_time_seconds) / 60, 0) AS avg_response").
		ColumnExpr("COALESCE(AVG(r.duration_seconds) / 60, 0) AS avg_completion").
		ColumnExpr("COALESCE(SUM(r.reopen_count), 0) AS total_reopen").
		Join("JOIN vendor_groups vg ON r.vendor_group_id = vg.id").
		GroupExpr("vg.group_name").
		OrderExpr("total DESC").
		Limit(5)

	err = applyFilters(q4).Scan(ctx, &vendorStats)
	for i := range vendorStats {
		if math.IsNaN(vendorStats[i].AvgResponseMinutes) {
			vendorStats[i].AvgResponseMinutes = 0
		}
		if math.IsNaN(vendorStats[i].AvgCompletionMinutes) {
			vendorStats[i].AvgCompletionMinutes = 0
		}
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch premium stats",
		})
	}

	// Build response
	return c.JSON(fiber.Map{
		"avg_response_time_minutes":   timeStats.AvgResponseMinutes,
		"avg_completion_time_minutes": timeStats.AvgCompletionMinutes,
		"scheduled_count":             timeStats.ScheduledCount,
		"reopen_count":                timeStats.ReopenCount,
		"daily_counts":                dailyStats,
		"vendor_stats":                vendorStats,
	})
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

// ReopenRequest handles reopening a completed request
func (h *RequestHandler) ReopenRequest(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	requestID := c.Params("id")
	ctx := context.Background()

	// Fetch request and verify ownership
	request := new(models.Request)
	err := database.DB.NewSelect().
		Model(request).
		Relation("VendorGroup").
		Where("r.id = ?", requestID).
		Where("r.user_id = ?", userID).
		Where("r.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "Request not found",
		})
	}

	// Verify status is done
	if request.Status != models.StatusDone {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Only completed requests can be reopened",
		})
	}

	now := time.Now()

	// Update request: set status to in_progress, clear finished_at and duration
	// Keep started_at to continue timer from original start time
	_, err = database.DB.NewUpdate().
		Model((*models.Request)(nil)).
		Set("status = ?", models.StatusInProgress).
		Set("reopened_at = ?", now).
		Set("reopen_count = reopen_count + 1").
		Set("finished_at = NULL").
		Set("duration_seconds = NULL").
		Where("id = ?", request.ID).
		Exec(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to reopen request",
		})
	}

	// Reload and return
	database.DB.NewSelect().Model(request).Relation("VendorGroup").Where("id = ?", request.ID).Scan(ctx)

	// Decrypt fields
	if request.Title == "" && request.TitleEncrypted != "" {
		request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	}
	request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)
	request.FollowupLink, _ = h.cryptoService.DecryptPtr(request.FollowupLinkEncrypted)
	request.ResolutionNotes, _ = h.cryptoService.DecryptPtr(request.ResolutionNotesEncrypted)

	// Trigger notification for reopen
	if h.notificationService != nil {
		go h.notificationService.NotifyStatusChange(request, request.Title, models.StatusDone, models.StatusInProgress)
	}

	return c.JSON(request.ToResponse())
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

	// Decrypt - Title is now plain text, no need to decrypt
	// Only decrypt if Title is empty and TitleEncrypted exists (backward compatibility)
	if request.Title == "" && request.TitleEncrypted != "" {
		request.Title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	}
	request.FollowupLink, _ = h.cryptoService.DecryptPtr(request.FollowupLinkEncrypted)
	request.ResolutionNotes, _ = h.cryptoService.DecryptPtr(request.ResolutionNotesEncrypted)

	// If description is secured, don't expose it until PIN is verified
	if !request.IsDescriptionSecure {
		request.Description, _ = h.cryptoService.DecryptPtr(request.DescriptionEncrypted)
	}

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

	// Check if request is scheduled and time hasn't arrived yet
	if request.ScheduledTime != nil && time.Now().Before(*request.ScheduledTime) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Request is scheduled",
			"message": fmt.Sprintf("Request ini dijadwalkan untuk %s. Tombol akan aktif pada jam tersebut",
				request.ScheduledTime.Format("2 Jan 2006, 15:04")),
			"scheduled_time": request.ScheduledTime.Format(time.RFC3339),
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

	// Trigger notification for status change
	if h.notificationService != nil {
		go h.notificationService.NotifyStatusChange(request, request.Title, models.StatusWaiting, models.StatusInProgress)
	}

	return c.JSON(request.ToResponse())
}

// FinishResponsePayload for finishing response
type FinishResponsePayload struct {
	PICName               string  `json:"pic_name,omitempty"`
	CheckboxIssueMismatch bool    `json:"checkbox_issue_mismatch"`
	ResolutionNotes       *string `json:"resolution_notes,omitempty"`
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

	// Encrypt resolution notes if provided
	var resolutionNotesEncrypted *string
	if payload.ResolutionNotes != nil && *payload.ResolutionNotes != "" {
		encrypted, err := h.cryptoService.EncryptPtr(payload.ResolutionNotes)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Failed to encrypt resolution notes",
			})
		}
		resolutionNotesEncrypted = encrypted
	}

	// Update request
	_, err = database.DB.NewUpdate().
		Model((*models.Request)(nil)).
		Set("status = ?", models.StatusDone).
		Set("finished_at = ?", now).
		Set("end_ip = ?", clientIP).
		Set("end_pic = ?", endPIC).
		Set("duration_seconds = ?", durationSeconds).
		Set("checkbox_issue_mismatch = ?", payload.CheckboxIssueMismatch).
		Set("resolution_notes = ?", resolutionNotesEncrypted).
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
	request.ResolutionNotes, _ = h.cryptoService.DecryptPtr(request.ResolutionNotesEncrypted)

	// Trigger notification for status change
	if h.notificationService != nil {
		go h.notificationService.NotifyStatusChange(request, request.Title, models.StatusInProgress, models.StatusDone)
	}

	return c.JSON(request.ToResponse())
}

// GetSharePage serves a static HTML page for social sharing
func (h *RequestHandler) GetSharePage(c fiber.Ctx) error {
	token := c.Params("token")

	ctx := context.Background()
	request := new(models.Request)

	err := database.DB.NewSelect().
		Model(request).
		Where("url_token = ?", token).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Request not found")
	}

	// Hybrid Title: Use plaintext if available, otherwise decrypt (fallback)
	var title string
	if request.Title != "" {
		title = request.Title
	} else if request.TitleEncrypted != "" {
		title, _ = h.cryptoService.Decrypt(request.TitleEncrypted)
	} else {
		title = "Untitled Request"
	}

	// Generate Time Info
	var timeInfo string
	now := time.Now()

	// Determine effective status and time info
	status := request.Status
	if status == models.StatusWaiting && request.ScheduledTime != nil && request.ScheduledTime.After(now) {
		status = "scheduled"
		timeInfo = fmt.Sprintf("Dijadwalkan pada %s", request.ScheduledTime.Format("2 Jan 2006, 15:04"))
	} else {
		switch request.Status {
		case models.StatusWaiting:
			duration := now.Sub(request.CreatedAt)
			timeInfo = fmt.Sprintf("Menunggu selama %s", formatDuration(duration))
		case models.StatusInProgress:
			if request.StartedAt != nil {
				duration := now.Sub(*request.StartedAt)
				timeInfo = fmt.Sprintf("Sedang dikerjakan selama %s", formatDuration(duration))
			} else {
				timeInfo = "Sedang dikerjakan"
			}
		case models.StatusDone:
			if request.DurationSeconds != nil {
				duration := time.Duration(*request.DurationSeconds) * time.Second
				timeInfo = fmt.Sprintf("Selesai dalam %s", formatDuration(duration))
			} else {
				timeInfo = "Selesai"
			}
		}
	}

	// Prepare frontend URL
	frontendURL := "https://response-watch.web.app/t/" + token

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s | ResponseWatch</title>
    
    <!-- Open Graph / Facebook / WhatsApp -->
    <meta property="og:type" content="website">
    <meta property="og:url" content="%s">
    <meta property="og:title" content="%s">
    <meta property="og:description" content="Status: %s • %s">
    <meta property="og:site_name" content="ResponseWatch">
    
    <!-- Twitter -->
    <meta property="twitter:card" content="summary_large_image">
    <meta property="twitter:title" content="%s">
    <meta property="twitter:description" content="Status: %s • %s">
    
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f5; color: #18181b; }
        .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); max-width: 400px; width: 90%%; text-align: center; }
        h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
        p { color: #52525b; margin-bottom: 1.5rem; }
        .btn { display: inline-block; background-color: #000000ff; color: white; padding: 0.75rem 1.5rem; text-decoration: none; border-radius: 6px; font-weight: 500; transition: background-color 0.2s; }
        .btn:hover { background-color: #202020ff; }
    </style>
</head>
<body>
    <div class="card">
        <h1>%s</h1>
        <p>Status: <strong>%s</strong><br>%s</p>
        <a href="%s" class="btn">View Request</a>
    </div>
    <script>
        // Auto-redirect after short delay
        setTimeout(function() {
            window.location.href = "%s";
        }, 10);
    </script>
</body>
</html>`,
		title,            // Title tag
		frontendURL,      // og:url
		title,            // og:title
		status, timeInfo, // og:desc - MODIFIED to use status variable
		title,            // twitter:title
		status, timeInfo, // twitter:desc - MODIFIED to use status variable
		title,            // h1
		status, timeInfo, // p content - MODIFIED to use status variable
		frontendURL, // button href
		frontendURL, // script redirect
	)

	c.Set("Content-Type", "text/html")
	return c.SendString(html)
}

func formatDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	if totalSeconds < 60 {
		return fmt.Sprintf("%d detik", totalSeconds)
	}

	minutes := int(d.Minutes()) % 60
	hours := int(d.Hours()) % 24
	days := int(d.Hours()) / 24

	weeks := days / 7
	remainingDays := days % 7

	var parts []string
	if weeks > 0 {
		parts = append(parts, fmt.Sprintf("%d minggu", weeks))
	}
	if remainingDays > 0 {
		parts = append(parts, fmt.Sprintf("%d hari", remainingDays))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d jam", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d menit", minutes))
	}

	// Fallback if something weird happens (e.g. 0 minutes but > 60 seconds?)
	if len(parts) == 0 {
		return "0 menit"
	}

	return strings.Join(parts, " ")
}

// GetPublicRequestsByUsername handles getting requests by username (public monitoring)
func (h *RequestHandler) GetPublicRequestsByUsername(c fiber.Ctx) error {
	username := c.Params("username")
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Username is required",
		})
	}

	ctx := context.Background()

	// 1. Find user by username
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

	// 2. Fetch requests for this user
	// Only fetch necessary fields for Kanban/Monitoring
	var requests []models.Request

	// Check if user's profile is public
	if !user.IsPublic {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": "User not found",
		})
	}

	// Base query - is_public is at user level, not request level
	query := database.DB.NewSelect().
		Model(&requests).
		Where("user_id = ?", user.ID).
		Where("deleted_at IS NULL")

	// Filter by date range if provided, otherwise default to "today" (last 24h) or specific logic?
	// For public monitoring, usually we show active stuff or recent stuff.
	// Let's support query params similar to List, but maybe restricted.
	status := c.Query("status")
	if status != "" {
		query = query.Where("status = ?", status)
	}

	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	if startDate != "" {
		query = query.Where("created_at >= ?", startDate)
	}
	if endDate != "" {
		query = query.Where("created_at <= ?::date + INTERVAL '1 day'", endDate)
	}

	// Parse pagination params
	page := 1
	limit := 60
	if p, err := strconv.Atoi(c.Query("page", "1")); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(c.Query("limit", "60")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	offset := (page - 1) * limit

	// Get total count first
	total, err := query.Count(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to count requests",
		})
	}

	// Order by latest and apply pagination
	err = query.Order("created_at DESC").Limit(limit).Offset(offset).Scan(ctx)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch requests",
		})
	}

	// Decrypt titles (Description might be too heavy/private, maybe just Title?)
	// Let's decrypt both for now as it's "Public" monitoring.
	// NOTE: If privacy is a concern, we might mask some data.
	for i := range requests {
		// Title: use plain text if available, otherwise decrypt (backward compat)
		if requests[i].Title == "" && requests[i].TitleEncrypted != "" {
			requests[i].Title, _ = h.cryptoService.Decrypt(requests[i].TitleEncrypted)
		}
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
		"user": fiber.Map{
			"username":     user.Username,
			"full_name":    user.FullName,
			"organization": user.Organization,
		},
	})
}

// GetDashboardMonitoringRequests handles getting requests for the dashboard monitoring (authenticated)
func (h *RequestHandler) GetDashboardMonitoringRequests(c fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()

	// Parse date range params
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	var requests []models.Request

	query := database.DB.NewSelect().
		Model(&requests).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL")

	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	if startDate != "" {
		query = query.Where("created_at >= ?", startDate)
	}
	if endDate != "" {
		query = query.Where("created_at <= ?::date + INTERVAL '1 day'", endDate)
	}

	// Default sort
	err := query.Order("created_at DESC").Scan(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch requests",
		})
	}

	// Decrypt/fallback for title
	for i := range requests {
		if requests[i].Title == "" && requests[i].TitleEncrypted != "" {
			requests[i].Title, _ = h.cryptoService.Decrypt(requests[i].TitleEncrypted)
		}
		requests[i].Description, _ = h.cryptoService.DecryptPtr(requests[i].DescriptionEncrypted)
	}

	responses := make([]*models.RequestResponse, len(requests))
	for i := range requests {
		responses[i] = requests[i].ToResponse()
	}

	return c.JSON(fiber.Map{
		"requests": responses,
	})
}

// VerifyDescriptionPINPayload for PIN verification
type VerifyDescriptionPINPayload struct {
	PIN string `json:"pin"`
}

// VerifyDescriptionPIN handles verifying PIN for secured descriptions
func (h *RequestHandler) VerifyDescriptionPIN(c fiber.Ctx) error {
	token := c.Params("token")

	var payload VerifyDescriptionPINPayload
	if err := c.Bind().JSON(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	if payload.PIN == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "PIN is required",
		})
	}

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

	// Check if description is secured
	if !request.IsDescriptionSecure || request.DescriptionPINHash == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "This request does not have a secured description",
		})
	}

	// Hash the input PIN and compare
	hash := sha256.Sum256([]byte(payload.PIN))
	inputPINHash := hex.EncodeToString(hash[:])

	if inputPINHash != *request.DescriptionPINHash {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid PIN",
			"message": "PIN salah. Silakan coba lagi.",
		})
	}

	// Decrypt and return description
	description, _ := h.cryptoService.DecryptPtr(request.DescriptionEncrypted)

	return c.JSON(fiber.Map{
		"success":     true,
		"description": description,
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
