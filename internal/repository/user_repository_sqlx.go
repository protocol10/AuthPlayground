package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/protocol10/AuthPlayground/internal/model"
)

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepositiory(db *sqlx.DB) UserRepository {
	return &userRepo{db: db}
}

// Create implements [UserRepository].
func (u *userRepo) Create(ctx context.Context, user model.User) error {
	query := "INSERT INTO users (id, first_name, email, phone_mumber, password_hash, email_verification) VALUES ($1, $2, $3, $4, $5)"

	var lastInsertId int
	err := u.db.DB.QueryRow(query, user.ID, user.FirstName, user.Email, user.PhoneNumber, user.PasswordHash, user.EmailVerified).Scan(&lastInsertId)
	if err != nil {
		fmt.Println("Error in insertion", err)
		return err
	}
	return nil
}

// FindMyEmail implements [UserRepository].
func (u *userRepo) FindMyEmail(ctx context.Context, emailID string) (*model.User, error) {
	query := "SELECT * from users where email=$1 LIMIT 1"
	user := &model.User{}
	err := u.db.GetContext(ctx, user, query)
	return *user, err
}

func (r *userRepo) FindById(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `SELECT * FROM users WHERE id = $1`
	user := &model.User{}
	err := r.db.GetContext(ctx, user, query, id)
	return user, err
}

func (r *userRepo) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, id)
	return err
}
