package worker

import (
	"context"
	"log"
	"time"

	"github.com/protocol10/AuthPlayground/internal/repository"
)

func StartCleanupWorker(repo repository.TokenRepository) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("Token cleanup worker started - running every hour")

	for range ticker.C {
		err := repo.DeleteExpiredEmailVerifications(context.Background())
		if err != nil {
			log.Printf("Error cleaning expired email verifications: %v", err)
		}

		// Clean expired password resets
		err = repo.DeleteExpiredPasswordResets(context.Background())
		if err != nil {
			log.Printf("Error cleaning expired password resets: %v", err)
		}

		// Clean revoked + expired refresh tokens
		err = repo.DeleteExpiredRefreshTokens(context.Background())
		if err != nil {
			log.Printf("Error cleaning expired refresh tokens: %v", err)
		}
	}
}
