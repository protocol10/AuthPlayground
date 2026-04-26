package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/protocol10/AuthPlayground/internal/model"
)

type tokenRepo struct {
	db *sqlx.DB
}

// DeleteExpiredEmailVerifications implements [TokenRepository].
func (t *tokenRepo) DeleteExpiredEmailVerifications(ctx context.Context) error {
	_, err := t.db.Exec(`DELETE FROM email_verifications WHERE expires_at < $1`, time.Now())
	return err
}

// DeleteExpiredPasswordResets implements [TokenRepository].
func (t *tokenRepo) DeleteExpiredPasswordResets(ctx context.Context) error {
	_, err := t.db.Exec(`DELETE FROM password_resets WHERE expires_at < $1`, time.Now())
	return err
}

// DeleteExpiredRefreshTokens implements [TokenRepository].
func (t *tokenRepo) DeleteExpiredRefreshTokens(ctx context.Context) error {
	_, err := t.db.Exec(`DELETE FROM refresh_tokens WHERE (expires_at < $1 AND revoked = true)`, time.Now())
	return err
}

// CreatePasswordReset implements [TokenRepository].
func (t *tokenRepo) CreatePasswordReset(ctx context.Context, pr *model.PasswordReset) error {
	query := `INSERT INTO password_resets (id, user_id, token, expires_at)
              VALUES ($1, $2, $3, $4)`
	_, err := t.db.ExecContext(ctx, query, pr.ID, pr.UserID, pr.Token, pr.ExpiresAt)
	return err
}

// FindValidPasswordReset implements [TokenRepository].
func (t *tokenRepo) FindValidPasswordReset(ctx context.Context, token string) (*model.PasswordReset, error) {
	query := `SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW() AND used = false`
	pr := &model.PasswordReset{}
	err := t.db.GetContext(ctx, pr, query, token)
	return pr, err
}

// MarkPasswordResetUsed implements [TokenRepository].
func (t *tokenRepo) MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error {
	_, err := t.db.ExecContext(ctx, `UPDATE password_resets SET used = true WHERE id = $1`, id)
	return err
}

// CreateEmailVerification implements [TokenRepository].
func (t *tokenRepo) CreateEmailVerification(ctx context.Context, ev *model.EmailVerification) error {
	query := "INSERT INTO email_verification (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)"
	_, err := t.db.ExecContext(ctx, query, ev.ID, ev.UserID, ev.Token, ev.ExpiresAt)
	return err
}

// CreateRefreshToken implements [TokenRepository].
func (t *tokenRepo) CreateRefreshToken(ctx context.Context, rt *model.RefreshToken) error {
	query := "INSERT into refresh_tokens (id, user_id, token_hash, expires_at, user_agent, ip_address) VALUES ($1, $2, $3,$4,$5,$6)"
	_, err := t.db.ExecContext(ctx, query, rt.ID, rt.UserID, rt.TokenHash, rt.ExpiresAt, rt.UserAgent, rt.IPAddress)
	return err
}

// FindRefreshTokenByHash implements [TokenRepository].
func (t *tokenRepo) FindRefreshTokenByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	query := "SELECT * from refresh_tokens where token_hash=$1"
	model := &model.RefreshToken{}
	err := t.db.GetContext(ctx, model, query, hash)
	if err != nil {
		return nil, err
	}
	return model, err
}

// FindValidEmailVerification implements [TokenRepository].
func (t *tokenRepo) FindValidEmailVerification(ctx context.Context, token string) (*model.EmailVerification, error) {
	query := `SELECT * FROM email_verifications 
              WHERE token = $1 AND expires_at > NOW() AND used = false`
	ev := &model.EmailVerification{}
	err := t.db.GetContext(ctx, ev, query, token)
	return ev, err
}

// MarkEmailVerificationUsed implements [TokenRepository].
func (t *tokenRepo) MarkEmailVerificationUsed(ctx context.Context, id uuid.UUID) error {
	_, err := t.db.ExecContext(ctx, `UPDATE email_verifications SET used = true WHERE id = $1`, id)
	return err
}

// RevokeAllRefreshTokens implements [TokenRepository].
func (t *tokenRepo) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	panic("unimplemented")
}

// RevokeRefreshToken implements [TokenRepository].
func (t *tokenRepo) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	_, err := t.db.ExecContext(ctx, "UPDATE refresh_tokens SET revoked+true where id=$1", id)
	return err

}

func NewTokenRepository(db *sqlx.DB) TokenRepository {
	return &tokenRepo{db: db}
}
