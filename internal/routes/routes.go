package routes

import (
	"github.com/boscod/responsewatch/internal/handlers"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/services"
	"github.com/gofiber/fiber/v3"
)

func SetupRoutes(app *fiber.App, jwtService *services.JWTService, cryptoService *services.CryptoService, authService *services.AuthService) {
	// Initialize services
	emailService := services.NewEmailService()
	notificationService := services.NewNotificationService(emailService)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, jwtService)
	requestHandler := handlers.NewRequestHandler(cryptoService, notificationService)
	vendorGroupHandler := handlers.NewVendorGroupHandler()
	notificationHandler := handlers.NewNotificationHandler(notificationService)

	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"message": "ResponseWatch API is running",
		})
	})

	// API group
	api := app.Group("/api")

	// Health check
	api.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"message": "ResponseWatch API is running",
		})
	})

	// ==================
	// Public Auth Routes
	// ==================
	api.Post("/auth/register", authHandler.Register)
	api.Post("/auth/login", authHandler.Login)

	// ==================
	// Public Smart Link Routes (No Auth Required)
	// Rate limited: 10 requests per minute per IP
	// ==================
	public := api.Group("/public", middleware.RateLimitMiddleware())
	public.Get("/monitoring/:username", requestHandler.GetPublicRequestsByUsername)
	public.Get("/t/:token", requestHandler.GetByToken)
	public.Post("/t/:token/start", requestHandler.StartResponse)
	public.Post("/t/:token/finish", requestHandler.FinishResponse)
	public.Post("/t/:token/verify-pin", requestHandler.VerifyDescriptionPIN)
	public.Post("/requests", requestHandler.CreatePublic)
	public.Post("/requests/:username", requestHandler.CreatePublicForUser)

	// Share page (Static HTML) - Hosted at root /share/:token (no /api prefix)
	app.Get("/share/:token", requestHandler.GetSharePage)

	// ==================
	// Protected Routes (JWT + Session)
	// ==================
	protected := api.Group("", middleware.AuthMiddleware(jwtService))

	// Auth routes
	protected.Post("/auth/logout", authHandler.Logout)
	protected.Get("/auth/me", authHandler.Me)
	protected.Put("/auth/profile", authHandler.UpdateProfile)

	// Request routes
	protected.Get("/requests/stats", requestHandler.Stats)
	protected.Get("/requests/stats/premium", requestHandler.StatsPremium) // Add premium stats route
	// Add dedicated monitoring endpoint for dashboard
	protected.Get("/requests/monitoring", requestHandler.GetDashboardMonitoringRequests)
	protected.Get("/requests", requestHandler.List)
	protected.Post("/requests", requestHandler.Create)
	protected.Get("/requests/export", requestHandler.DownloadExcel)
	protected.Get("/requests/:id", requestHandler.Get)
	protected.Put("/requests/:id", requestHandler.Update)
	protected.Delete("/requests/:uuid", requestHandler.Delete)
	protected.Put("/requests/:id/reopen", requestHandler.ReopenRequest)
	protected.Put("/requests/:id/assign-vendor", requestHandler.AssignVendor)

	// Vendor Group routes
	protected.Get("/vendor-groups", vendorGroupHandler.List)
	protected.Post("/vendor-groups", vendorGroupHandler.Create)
	protected.Get("/vendor-groups/:id", vendorGroupHandler.Get)
	protected.Put("/vendor-groups/:id", vendorGroupHandler.Update)
	protected.Delete("/vendor-groups/:id", vendorGroupHandler.Delete)

	// Notification routes
	protected.Get("/notifications", notificationHandler.List)
	protected.Get("/notifications/unread-count", notificationHandler.UnreadCount)
	protected.Post("/notifications/:id/read", notificationHandler.MarkAsRead)
	protected.Post("/notifications/read-all", notificationHandler.MarkAllAsRead)

	// Note routes
	noteService := services.NewNoteService()
	noteHandler := handlers.NewNoteHandler(noteService)

	protected.Get("/notes", noteHandler.GetNotes)
	protected.Get("/notes/reminders", noteHandler.GetUpcomingReminders)
	protected.Post("/notes", noteHandler.CreateNote)
	protected.Put("/notes/:id", noteHandler.UpdateNote)
	protected.Delete("/notes/:id", noteHandler.DeleteNote)
}
