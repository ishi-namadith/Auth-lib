package auth

import (
	"context"
	"time"
)

type AuthService interface {
    GenerateAccessToken(ctx context.Context, userID string, claims map[string]interface{}) (string, error)
    GenerateRefreshToken(ctx context.Context, userID string) (string, error)
    ValidateToken(ctx context.Context, token string) (map[string]interface{}, error)
    BlacklistToken(ctx context.Context, acess_token string, refresh_token string, access_ExpiresAt time.Time, refresh_expiresAt time.Time) error
    Logout(ctx context.Context, refreshToken string, accessToken string) error
}

type Storage interface {
    SaveRefreshToken(ctx context.Context, userID string, token string, expiresAt time.Time) error
    DeleteRefreshToken(ctx context.Context, token string) error
    HasRouteAccess(ctx context.Context, userID, path, method string) (bool, error)
}

type InMemory interface {
    Add(token string, expiresAt time.Time)
    Cleanup(token string, expiresAt time.Time)
    IsBlacklisted(token string) bool
}
