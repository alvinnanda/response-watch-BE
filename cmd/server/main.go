package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/boscod/responsewatch/config"
	"github.com/boscod/responsewatch/internal/database"
	"github.com/boscod/responsewatch/internal/middleware"
	"github.com/boscod/responsewatch/internal/rabbitmq"
	"github.com/boscod/responsewatch/internal/routes"
	"github.com/boscod/responsewatch/internal/services"
	workers "github.com/boscod/responsewatch/internal/worker"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	log.Printf("Connected to database successfully")
	_ = db // Mark as used

	// Initialize services
	jwtService := services.NewJWTService(cfg.JWTSecret, 168) // 7 days
	cryptoService := services.NewCryptoService(cfg.AppSecret)
	authService := services.NewAuthService(jwtService, cryptoService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:       "ResponseWatch API",
		CaseSensitive: true,
		StrictRouting: false,
		ServerHeader:  "ResponseWatch",
		ErrorHandler:  customErrorHandler,
	})

	// Global middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c fiber.Ctx, e any) {
			log.Printf("🔥 PANIC RECOVERED: %v", e)
			log.Printf("📍 Request: %s %s", c.Method(), c.Path())
			log.Printf("📋 Stack Trace:\n%s", string(debug.Stack()))
		},
	}))
	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${status} - ${method} ${path} (${latency})\n",
		TimeFormat: "2006-01-02 15:04:05",
	}))
	app.Use(middleware.CORSMiddleware(cfg.AllowedOrigins))

	// Setup RabbitMQ
	if cfg.RabbitMQURL != "" {
		if err := rabbitmq.SetupRabbitMQ(cfg.RabbitMQURL); err != nil {
			log.Printf("Failed to connect to RabbitMQ: %v", err)
			// Proceed without RabbitMQ? Or fail?
			// For this feature, maybe just log error but allow server to run (graceful degradation)
		} else {
			// Context for worker cancellation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start Worker (services initialized lazily inside goroutine)
			go func() {
				// Lazy initialize services only when worker starts
				noteService := services.NewNoteService()
				emailService := services.NewEmailService()
				whatsappService := services.NewWhatsAppService()
				notificationService := services.NewNotificationService(emailService)
				noteWorker := workers.NewNoteWorker(noteService, emailService, whatsappService, notificationService)

				if err := noteWorker.StartWorker(ctx); err != nil {
					log.Printf("Worker failed: %v", err)
				}
			}()

			defer rabbitmq.Close()
		}
	}

	// Setup routes
	routes.SetupRoutes(app, jwtService, cryptoService, authService)

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down server...")
		if err := app.Shutdown(); err != nil {
			log.Printf("Error shutting down: %v", err)
		}
	}()

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting server on %s", addr)
	log.Printf("Environment: %s", cfg.Env)
	log.Printf("Allowed origins: %v", cfg.AllowedOrigins)

	if err := app.Listen(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func customErrorHandler(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   "Error",
		"message": err.Error(),
	})
}
