package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/protocol10/AuthPlayground/internal/config"
	"github.com/protocol10/AuthPlayground/internal/handler"
	"github.com/protocol10/AuthPlayground/internal/repository"
	"github.com/protocol10/AuthPlayground/internal/service"
	"github.com/protocol10/AuthPlayground/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	// Database
	db, err := sqlx.Connect("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("error closing database: %v", err)
		}
	}()

	// Repositories
	userRepo := repository.NewUserRepositiory(db)
	tokenRepo := repository.NewTokenRepository(db)

	// Service
	authService := service.NewAuthService(userRepo, tokenRepo, cfg.JWTSecret)

	// Handler
	authHandler := handler.NewAuthHandler(authService)

	// Gin Router
	r := gin.Default()

	r.POST("/signup", authHandler.Signup)
	r.POST("/signup", authHandler.Signup)
	r.POST("/signin", authHandler.Signin)
	r.POST("/refresh", authHandler.RefreshToken)
	r.GET("/verify-email", authHandler.VerifyEmail)
	r.POST("/logout", authHandler.Logout)
	r.POST("/forgot-password", authHandler.ForgotPassword)

	// Start cleanup worker
	go worker.StartCleanupWorker(tokenRepo)

	log.Printf("Auth service running on :%s", cfg.ServerPort)
	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
