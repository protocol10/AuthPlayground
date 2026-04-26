package service

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/protocol10/AuthPlayground/internal/middleware"
	"github.com/protocol10/AuthPlayground/internal/model"
	"github.com/protocol10/AuthPlayground/internal/repository"
	"github.com/protocol10/AuthPlayground/internal/util"
)

type AuthService struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	jwtSecret string
}

func NewAuthService(userRepo repository.UserRepository, tokenRepo repository.TokenRepository, jwtSecret string) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwtSecret: jwtSecret,
	}
}

func (s *AuthService) Signup(ctx context.Context, firstName, email, password, phone string) (*model.User, error) {
	// Check if user exists
	if _, err := s.userRepo.FindMyEmail(ctx, email); err == nil {
		return nil, errors.New("email already registered")
	}

	hashedPassword, err := util.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := model.User{
		ID:           uuid.New(),
		FirstName:    firstName,
		Email:        email,
		PhoneNumber:  &phone,
		PasswordHash: hashedPassword,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Create email verification token
	ev := &model.EmailVerification{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.tokenRepo.CreateEmailVerification(ctx, ev); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *AuthService) Signin(ctx context.Context, email, password, userAgent, ip string) (string, string, error) {
	user, err := s.userRepo.FindMyEmail(ctx, email)
	if err != nil || !user.EmailVerified {
		return "", "", errors.New("invalid credentials")
	}

	if !util.ChecKPasswordHash(password, user.PasswordHash) {
		return "", "", errors.New("invalid credentials")
	}

	// Generate Access Token

	accessToken, err := middleware.GenerateAccessToken(user.ID, user.Email, s.jwtSecret)
	if err != nil {
		return "", "", err
	}

	// Create Refresh Token
	refreshStr := uuid.New().String()
	refreshHash, _ := util.HashPassword(refreshStr) // reuse same hash function

	rt := &model.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
		UserAgent: userAgent,
		IPAddress: ip,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, rt); err != nil {
		return "", "", err
	}

	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		// log but don't fail
		log.Printf("failed to update last login for user %s: %v", user.ID, err)
	}

	return accessToken, refreshStr, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, oldRefreshStr, userAgent, ip string) (string, string, error) {
	if oldRefreshStr == "" {
		return "", "", errors.New("refresh token required")
	}

	oldHash, _ := util.HashPassword(oldRefreshStr)
	rt, err := s.tokenRepo.FindRefreshTokenByHash(ctx, oldHash)
	if err != nil || rt.Revoked || time.Now().After(rt.ExpiresAt) {
		return "", "", errors.New("invalid or expired refresh token")
	}

	user, err := s.userRepo.FindById(ctx, rt.UserID)
	if err != nil {
		return "", "", err
	}

	// Rotation: Revoke old token
	_ = s.tokenRepo.RevokeRefreshToken(ctx, rt.ID)

	// New Access Token
	newAccess, _ := middleware.GenerateAccessToken(user.ID, user.Email, s.jwtSecret)

	// New Refresh Token
	newRefreshStr := uuid.New().String()
	newHash, _ := util.HashPassword(newRefreshStr)

	newRT := &model.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: newHash,
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
		UserAgent: userAgent,
		IPAddress: ip,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, newRT); err != nil {
		return "", "", err
	}

	return newAccess, newRefreshStr, nil
}

// ====================================
// Verify Email
// ====================================
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	ev, err := s.tokenRepo.FindValidEmailVerification(ctx, token)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Mark user as verified
	// Note: You might want to add UpdateEmailVerified method in UserRepository
	err = s.tokenRepo.MarkEmailVerificationUsed(ctx, ev.UserID)
	if err != nil {
		return err
	}

	return s.tokenRepo.MarkEmailVerificationUsed(ctx, ev.ID)
}

// ====================================
// Logout
// ====================================
func (s *AuthService) Logout(ctx context.Context, refreshStr string) {
	if refreshStr == "" {
		return
	}
	hash, _ := util.HashPassword(refreshStr)
	rt, err := s.tokenRepo.FindRefreshTokenByHash(ctx, hash)
	if err == nil {
		_ = s.tokenRepo.RevokeRefreshToken(ctx, rt.ID)
	}
}

// ====================================
// Forgot Password (Basic version)
// ====================================
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.FindMyEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal if email exists (security)
	}

	// Create password reset token
	reset := &model.PasswordReset{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := s.tokenRepo.CreatePasswordReset(ctx, reset); err != nil {
		return err
	}
	log.Println("Password reset token for ")

	// TODO: Save to DB + send email via Kafka
	// For now, just returning success
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	pr, err := s.tokenRepo.FindValidPasswordReset(ctx, token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Hash new password
	hashed, err := util.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update user password
	err = s.userRepo.UpdatePassword(ctx, pr.UserID, hashed)
	if err != nil {
		return err
	}

	// Mark token as used
	return s.tokenRepo.MarkPasswordResetUsed(ctx, pr.ID)
}
