package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ServerPort         string        `envconfig:"SERVER_PORT" default:"8080"`
	DatabaseURL        string        `envconfig:"DATABASE_URL" default:"postgres://postgres:postgres@localhost:5432/authdb?sslmode=disable"`
	JWTSecret          string        `envconfig:"JWT_SECRET" required:"true"`
	AccessTokenExpiry  time.Duration `envconfig:"ACCESS_TOKEN_EXPIRY" default:"15m"`
	RefreshTokenExpiry time.Duration `envconfig:"REFRESH_TOKEN_EXPIRY" default:"90d"`
}

func Load() (*Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	return &cfg, err
}
