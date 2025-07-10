package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authService struct {
	config Config
	storage Storage
	blacklist InMemory
}

func NewAuthService(config Config, storage Storage , blacklist InMemory) AuthService {
    return &authService{
        config:    config,
        storage:   storage,
        blacklist: blacklist,
    }
}

func (s *authService) GenerateAccessToken(ctx context.Context, userID string, claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.AccessTokenExp),
        "iat": time.Now().Unix(),
    })
    for key, value := range claims {
        token.Claims.(jwt.MapClaims)[key] = value
    }
    return token.SignedString([]byte(s.config.AccessTokenSecret))
}

func (s *authService) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.RefreshTokenExp).Unix(),
        "iat": time.Now().Unix(),
    })
    tokenStr, err := token.SignedString([]byte(s.config.RefreshTokenSecret))
    if err != nil {
        return "", err
    }
    err = s.storage.SaveRefreshToken(ctx, userID, tokenStr, time.Now().Add(s.config.RefreshTokenExp))
    return tokenStr, err
}

func (s *authService) ValidateToken(ctx context.Context, tokenStr string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("invalid signing method")
        }
        return []byte(s.config.AccessTokenSecret), nil
    })
    if err != nil || !token.Valid {
        return nil, errors.New("invalid token")
    }
    return token.Claims.(jwt.MapClaims), nil
}

func (s *authService) BlacklistToken(ctx context.Context, acess_token string, refresh_token string, access_expiresAt time.Time, refresh_expiresAt time.Time) error {
    s.blacklist.Add(acess_token, access_expiresAt)
    s.blacklist.Add(refresh_token, refresh_expiresAt)
    err := s.storage.DeleteRefreshToken(ctx, refresh_token) 
	return err
}

func (s *authService) Logout(ctx context.Context, refreshToken string , accessToken string) error {
    refresh_claims, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.RefreshTokenSecret), nil
    })
    if err != nil || !refresh_claims.Valid {
        return errors.New("invalid refresh token")
    }
    access_claims, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.AccessTokenSecret), nil
    })
    if err != nil || !access_claims.Valid {
        return errors.New("invalid access token")
    }
    access_expiresAt := time.Unix(int64(access_claims.Claims.(jwt.MapClaims)["exp"].(float64)), 0)
    refresh_expiresAt := time.Unix(int64(refresh_claims.Claims.(jwt.MapClaims)["exp"].(float64)), 0)
    err = s.BlacklistToken(ctx, accessToken, refreshToken, access_expiresAt, refresh_expiresAt)
    return err
}
