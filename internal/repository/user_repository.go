package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/protocol10/AuthPlayground/internal/model"
)

type UserRepository interface {
	Create(ctx context.Context, user model.User) error
	FindMyEmail(ctx context.Context, emailID string) (*model.User, error)
	FindById(ctx context.Context, id uuid.UUID) (*model.User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}

type TokenRepository interface {
	CreateEmailVerification(ctx context.Context, ev *model.EmailVerification) error
	FindValidEmailVerification(ctx context.Context, token string) (*model.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id uuid.UUID) error

	DeleteExpiredEmailVerifications(ctx context.Context) error
	DeleteExpiredPasswordResets(ctx context.Context) error
	DeleteExpiredRefreshTokens(ctx context.Context) error

	CreateRefreshToken(ctx context.Context, rt *model.RefreshToken) error
	FindRefreshTokenByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
	RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error

	CreatePasswordReset(ctx context.Context, pr *model.PasswordReset) error
	FindValidPasswordReset(ctx context.Context, token string) (*model.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error
}
