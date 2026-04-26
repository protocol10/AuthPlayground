package model

import (
	"time"

	"github.com/google/uuid"
)

// User table
type User struct {
	ID            uuid.UUID  `db:"id"`
	FirstName     string     `db:"first_name"`
	Email         string     `db:"email"`
	PhoneNumber   *string    `db:"phone_number"`
	PasswordHash  string     `db:"password_hash"`
	EmailVerified bool       `db:"email_verified"`
	LastLoginAt   *time.Time `db:"last_login_at"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
}

// EmailVerification one time action token
type EmailVerification struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
	CreatedAt time.Time `db:"created_at"`
}

// Password reset - one time action token
type PasswordReset struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
	CreatedAt time.Time `db:"created_at"`
}

// Refreshtoken  - used for renewal of session
type RefreshToken struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	ExpiresAt time.Time `db:"expires_at"`
	Revoked   bool      `db:"revoked"`
	UserAgent string    `db:"user_agent"`
	IPAddress string    `db:"ip_address"`
	CreatedAt time.Time `db:"created_at"`
}
