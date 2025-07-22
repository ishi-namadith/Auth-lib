package authentication

import (
	"context"
	"errors"
	"time"
    "fmt"
	"github.com/golang-jwt/jwt/v5"
    "encoding/hex"
    "crypto/sha256"
)

type authService struct {
	config Config
	blacklist InMemory
    routeAccess RouteAccess
}

type authServiceV2 struct {
	config Config
	storage Storage
    blacklist InMemory
} 
// with inmemomory with inmemory Rote Access
func NewAuthService(config Config, blacklist InMemory , routeAccess RouteAccess) AuthService {
    return &authService{
        config:    config,
        blacklist: blacklist,
        routeAccess: routeAccess,
    }
}
// without inmemomory without inmemory Rote Access
func NewAuthServiceWithoutInMemoryRA(config Config, storage Storage, blacklist InMemory) AuthServiceV2 {
	return &authServiceV2{
		config:    config,
		storage:   storage,
        blacklist: blacklist,
	}
}

func (s *authService) GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.AccessTokenExp).Unix(),
        "iat": time.Now().Unix(),
    })
    for key, value := range claims {
        token.Claims.(jwt.MapClaims)[key] = value
    }
    return token.SignedString([]byte(s.config.AccessTokenSecret))
}

func (s *authService) GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.RefreshTokenExp).Unix(),
        "iat": time.Now().Unix(),
    })
    for key, value := range claims {
        token.Claims.(jwt.MapClaims)[key] = value
    }
    tokenStr, err := token.SignedString([]byte(s.config.RefreshTokenSecret))
    if err != nil {
        return "", err
    }
    return tokenStr, err
}

func (s *authService) ValidateAccessToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error) {
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

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid claims format")
    }

    exp, ok := claims["exp"].(float64)
    if !ok {
        return nil, errors.New("expiration claim missing or invalid")
    }

    expTime := time.Unix(int64(exp), 0)

    fpHashRaw, ok := claims["fingerPRT"]
    if !ok {
        return nil, errors.New("fingerprint hash missing in token")
    }

    fpHashStr, ok := fpHashRaw.(string)
    if !ok {
        return nil, errors.New("invalid fingerprint hash format")
    }

    hasher := sha256.New()
    hasher.Write([]byte(fingerPRT))
    hashedFingerPRT := hex.EncodeToString(hasher.Sum(nil))

    if fpHashStr != hashedFingerPRT {
        s.blacklist.Add(tokenStr, expTime)
        if err != nil {
            return nil, fmt.Errorf("failed to delete refresh token: %w", err)
        }
        return nil, errors.New("fingerprint mismatch")
    }

    return claims, nil
}

func (s *authService) ValidateRefreshToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("invalid signing method")
        }
        return []byte(s.config.RefreshTokenSecret), nil
    })
    
    if err != nil || !token.Valid {
        return nil, errors.New("invalid refresh token")
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid claims format")
    }

    exp, ok := claims["exp"].(float64)
    if !ok {
        return nil, errors.New("expiration claim missing or invalid")
    }

    expTime := time.Unix(int64(exp), 0)

    fpHashRaw, ok := claims["fingerPRT"]
    if !ok {
        return nil, errors.New("fingerprint hash missing in token")
    }

    fpHashStr, ok := fpHashRaw.(string)
    if !ok {
        return nil, errors.New("invalid fingerprint hash format")
    }

    hasher := sha256.New()
    hasher.Write([]byte(fingerPRT))
    hashedFingerPRT := hex.EncodeToString(hasher.Sum(nil))

    if fpHashStr != hashedFingerPRT {
        s.blacklist.Add(tokenStr, expTime)
        if err != nil {
            return nil, fmt.Errorf("failed to delete refresh token: %w", err)
        }
        return nil, errors.New("fingerprint mismatch")
    }
    return claims, nil
}

func (s *authService) CreateRoleAccess(ctx context.Context, userRole, path, method string) error {
    return s.routeAccess.AddRoleAccess(userRole, path, method)
}

func (s *authService) RemoveRoleAccess(ctx context.Context, userRole, path, method string) error {
    return s.routeAccess.RemoveRoleAccess(userRole, path, method)
}
func (s *authService) HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error) {
    exists := s.routeAccess.HasRoleAccess(userRole, path, method)
    return exists, nil
}

func (s *authService) CreatePolicyAccess(ctx context.Context, userID int, policy string) error {
    return s.routeAccess.AddPolicyAccess(userID, policy)
}

func (s *authService) RemovePolicyAccess(ctx context.Context, userID int, policy string) error {
    return s.routeAccess.RemovePolicyAccess(userID, policy)
}

func (s *authService) HasPolicyAccess(ctx context.Context, userID int, policy string) (bool, error) {
    exists := s.routeAccess.HasPolicyAccess(userID, policy)
    return exists, nil
}

func (s *authService) Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error {
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
    s.blacklist.Add(refreshToken, refresh_expiresAt)
    s.blacklist.Add(accessToken, access_expiresAt)
    return err
}

func (s *authServiceV2) GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.AccessTokenExp).Unix(),
        "iat": time.Now().Unix(),
    })
    for key, value := range claims {
        token.Claims.(jwt.MapClaims)[key] = value
    }
    return token.SignedString([]byte(s.config.AccessTokenSecret))
}

func (s *authServiceV2) GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(s.config.RefreshTokenExp).Unix(),
        "iat": time.Now().Unix(),
    })
    for key, value := range claims {
        token.Claims.(jwt.MapClaims)[key] = value
    }
    tokenStr, err := token.SignedString([]byte(s.config.RefreshTokenSecret))
    if err != nil {
        return "", err
    }
    return tokenStr, err
}

func (s *authServiceV2) ValidateAccessToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error) {
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

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid claims format")
    }

    exp, ok := claims["exp"].(float64)
    if !ok {
        return nil, errors.New("expiration claim missing or invalid")
    }

    expTime := time.Unix(int64(exp), 0)

    fpHashRaw, ok := claims["fingerPRT"]
    if !ok {
        return nil, errors.New("fingerprint hash missing in token")
    }

    fpHashStr, ok := fpHashRaw.(string)
    if !ok {
        return nil, errors.New("invalid fingerprint hash format")
    }

    hasher := sha256.New()
    hasher.Write([]byte(fingerPRT))
    hashedFingerPRT := hex.EncodeToString(hasher.Sum(nil))

    if fpHashStr != hashedFingerPRT {
        s.blacklist.Add(tokenStr, expTime)
        return nil, errors.New("fingerprint mismatch")
    }

    return claims, nil
}

func (s *authServiceV2) ValidateRefreshToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("invalid signing method")
        }
        return []byte(s.config.RefreshTokenSecret), nil
    })
    
    if err != nil || !token.Valid {
        return nil, errors.New("invalid refresh token")
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid claims format")
    }
    exp, ok := claims["exp"].(float64)
    if !ok {
        return nil, errors.New("expiration claim missing or invalid")
    }

    expTime := time.Unix(int64(exp), 0)

    fpHashRaw, ok := claims["fingerPRT"]
    if !ok {
        return nil, errors.New("fingerprint hash missing in token")
    }

    fpHashStr, ok := fpHashRaw.(string)
    if !ok {
        return nil, errors.New("invalid fingerprint hash format")
    }

    hasher := sha256.New()
    hasher.Write([]byte(fingerPRT))
    hashedFingerPRT := hex.EncodeToString(hasher.Sum(nil))

    if fpHashStr != hashedFingerPRT {
        s.blacklist.Add(tokenStr, expTime)
        return nil, errors.New("fingerprint mismatch")
    }
    return claims, nil
}

func (s *authServiceV2) CreateRoleAccess(ctx context.Context, userRole, path, method string) error {
    return s.storage.AddRoleAccess(ctx, userRole, path, method)
}

func (s *authServiceV2) CheckRoleAccess(ctx context.Context, userRole, path, method string) (bool, error) {
    return s.storage.HasRoleAccess(ctx, userRole, path, method)
}

func (s *authServiceV2) RemoveRoleAccess(ctx context.Context, userRole, path, method string) error {
    return s.storage.DeleteRoleAccess(ctx, userRole, path, method)
}

func (s *authServiceV2) CreatePolicyAccess(ctx context.Context, userID int, policy string) error {
    return s.storage.AddPolicyAccess(ctx, userID, policy)
}

func (s *authServiceV2) CheckPolicyAccess(ctx context.Context, userID int, policy string) (bool, error) {
    return s.storage.HasPolicyAccess(ctx, userID, policy)
}

func (s *authServiceV2) RemovePolicyAccess(ctx context.Context, userID int, policy string) error {
    return s.storage.DeletePolicyAccess(ctx, userID, policy)
}

func (s *authServiceV2) Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error {
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
    s.blacklist.Add(refreshToken, refresh_expiresAt)
    s.blacklist.Add(accessToken, access_expiresAt)
    return err
}


