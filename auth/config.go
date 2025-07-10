package auth

import (
	"time"
)

type Config struct {
    AccessTokenSecret  string
    RefreshTokenSecret string
    AccessTokenExp     time.Duration
    RefreshTokenExp    time.Duration
}