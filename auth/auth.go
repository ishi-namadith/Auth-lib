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
    storage Storage
	blacklist InMemory
    routeAccess RouteAccess
    otpStore    OTPStore
    emailService EmailService 
}

type authServiceV2 struct {
	config Config
	storage Storage
    blacklist InMemory
    otpStore    OTPStore
    emailService EmailService
}

// with inmemomory with inmemory Rote Access
func NewAuthService(config Config, storage Storage, blacklist InMemory, routeAccess RouteAccess, otpStore OTPStore) AuthService {
    emailService := NewEmailService(config.EmailConfig)
    return &authService{
        config:       config,
        storage:      storage,
        blacklist:    blacklist,
        routeAccess:  routeAccess,
        otpStore:     otpStore,
        emailService: emailService,
    }
}

// without inmemomory without inmemory Rote Access
func NewAuthServiceWithoutInMemoryRA(config Config, storage Storage, blacklist InMemory, otpStore OTPStore) AuthServiceV2 {
    emailService := NewEmailService(config.EmailConfig)
	return &authServiceV2{
		config:    config,
		storage:   storage,
        blacklist: blacklist,
        otpStore:  otpStore,
        emailService: emailService,
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

func (s *authService) ValidateAccessToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(ctx ,tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    RC_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    if s.blacklist.IsBlacklisted(ctx ,RC_ID) {
        return nil, errors.New("token is blacklisted due to role change")
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
        err :=s.blacklist.Add(ctx ,tokenStr, expTime)
        if err != nil {
            return nil, fmt.Errorf("failed to delete refresh token: %w", err)
        }
        return nil, errors.New("fingerprint mismatch")
    }

    return claims, nil
}

func (s *authService) ValidateRefreshToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(ctx ,tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    RC_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    if s.blacklist.IsBlacklisted(ctx ,RC_ID) {
        return nil, errors.New("token is blacklisted due to role change")
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
        err:= s.blacklist.Add(ctx, tokenStr, expTime)
        if err!= nil {
            return nil, fmt.Errorf("failed to delete refresh token: %w", err)
        }
        return nil, errors.New("fingerprint mismatch")
    }
    return claims, nil
}

func (s *authService) CreateRoleAccess(ctx context.Context, userRole, path, method string) error {
    err := s.routeAccess.AddRoleAccess(ctx,userRole, path, method)
    if err != nil {
        return fmt.Errorf("failed to create role access: %w", err)
    }
    err = s.storage.AddRoleAccess(ctx, userRole, path, method)
    if err != nil {
        return fmt.Errorf("failed to create role access: %w", err)
    }
    return nil
}

func (s *authService) RemoveRoleAccess(ctx context.Context, userRole, path, method string) error {
    err := s.routeAccess.RemoveRoleAccess(ctx, userRole, path, method)
    if err != nil {
        return fmt.Errorf("failed to remove role access: %w", err)
    }
    err = s.storage.DeleteRoleAccess(ctx, userRole, path, method)
    if err != nil {
        return fmt.Errorf("failed to remove role access: %w", err)
    }
    return nil
}

func (s *authService) HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error) {
    exists := s.routeAccess.HasRoleAccess(ctx, userRole, path, method)
    return exists, nil
}

func (s *authService) CreatePolicyAccess(ctx context.Context, userRole, policy string) error {
    err := s.routeAccess.AddPolicyAccess(ctx, userRole, policy)
    if err != nil {
        return fmt.Errorf("failed to create policy access: %w", err)
    }
    err = s.storage.AddRolePolicyAccess(ctx, userRole, policy)
    if err != nil {
        return fmt.Errorf("failed to create policy access: %w", err)
    }
    return nil
}

func (s *authService) RemovePolicyAccess(ctx context.Context, userRole, policy string) error {
    err := s.routeAccess.RemovePolicyAccess(ctx, userRole, policy)
    if err != nil {
        return fmt.Errorf("failed to remove policy access: %w", err)
    }
    err = s.storage.DeleteRolePolicyAccess(ctx, userRole, policy)
    if err != nil {
        return fmt.Errorf("failed to remove policy access: %w", err)
    }
    return nil
}

func (s *authService) HasPolicyAccess(ctx context.Context, userRole, policy string) (bool, error) {
    exists := s.routeAccess.HasPolicyAccess(ctx, userRole, policy)
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

    accessClaims, ok := access_claims.Claims.(jwt.MapClaims)
    if !ok {
        return errors.New("invalid access token claims format")
    }
    
    accessExp, ok := accessClaims["exp"].(float64)
    if !ok {
        return errors.New("invalid access token expiration")
    }
    access_expiresAt := time.Unix(int64(accessExp), 0)

    refreshClaims, ok := refresh_claims.Claims.(jwt.MapClaims)
    if !ok {
        return errors.New("invalid refresh token claims format")
    }
    
    refreshExp, ok := refreshClaims["exp"].(float64)
    if !ok {
        return errors.New("invalid refresh token expiration")
    }
    refresh_expiresAt := time.Unix(int64(refreshExp), 0)
    
    s.blacklist.Add(ctx, refreshToken, refresh_expiresAt)
    s.blacklist.Add(ctx ,accessToken, access_expiresAt)
    return nil 
}

func (s *authService) InvalidateTokenOnRoleChange(ctx context.Context, userID int, userRole string ) error {
    Rc_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    exp := time.Now().Add(s.config.RefreshTokenExp)
    s.blacklist.Add(ctx, Rc_ID, exp)
    return nil
}

func (s *authService) ReloadRoleAccessCache(ctx context.Context) error {
    roles, err := s.storage.GetAllRoleAccess(ctx)
    if err != nil {
        return fmt.Errorf("failed to get role access from storage: %w", err)
    }

    err = s.routeAccess.ReloadRoleAccess(ctx, roles)
    if err != nil {
        return fmt.Errorf("failed to reload role access cache: %w", err)
    }
    
    return nil
}

func (s *authService) ReloadPolicyAccessCache(ctx context.Context) error {
    policies, err := s.storage.GetAllPolicyAccess(ctx)
    if err != nil {
        return fmt.Errorf("failed to get policy access from storage: %w", err)
    }

    err = s.routeAccess.ReloadPolicyAccess(ctx, policies)
    if err != nil {
        return fmt.Errorf("failed to reload policy access cache: %w", err)
    }
    
    return nil
}

func (s *authService) ReloadAllCaches(ctx context.Context) error {
    if err := s.routeAccess.ClearAllCache(ctx); err != nil {
        return fmt.Errorf("failed to clear caches: %w", err)
    }

    if err := s.ReloadRoleAccessCache(ctx); err != nil {
        return fmt.Errorf("failed to reload role access cache: %w", err)
    }

    if err := s.ReloadPolicyAccessCache(ctx); err != nil {
        return fmt.Errorf("failed to reload policy access cache: %w", err)
    }
    
    return nil
}

func (s *authService) InitiatePasswordReset(ctx context.Context, email string) error {
    otp, err := GenerateOTP(6)
    if err != nil {
        return fmt.Errorf("failed to generate OTP: %w", err)
    }

    // Store OTP with 15 minutes expiry
    err = s.otpStore.StoreOTP(ctx, email, otp, 15*time.Minute)
    if err != nil {
        return fmt.Errorf("failed to store OTP: %w", err)
    }

    // Send OTP via email
    err = s.emailService.SendOTP(email, otp)
    if err != nil {
        // delete otp if fails
        s.otpStore.DeleteOTP(ctx, email)
        return fmt.Errorf("failed to send OTP email: %w", err)
    }

    return nil
}

func (s *authService) VerifyPasswordResetOTP(ctx context.Context, email string, otp string) error {
    valid, err := s.otpStore.VerifyOTP(ctx, email, otp)
    if err != nil {
        return fmt.Errorf("failed to verify OTP: %w", err)
    }
    if !valid {
        return errors.New("invalid OTP")
    }

    // Delete OTP after successful verification
    err = s.otpStore.DeleteOTP(ctx, email)
    if err != nil {
        return fmt.Errorf("failed to delete OTP: %w", err)
    }

    return nil
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

func (s *authServiceV2) ValidateAccessToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(ctx, tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    RC_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    if s.blacklist.IsBlacklisted(ctx, RC_ID) {
        return nil, errors.New("token is blacklisted due to role change")
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
        s.blacklist.Add(ctx, tokenStr, expTime)
        return nil, errors.New("fingerprint mismatch")
    }

    return claims, nil
}

func (s *authServiceV2) ValidateRefreshToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error) {
    if s.blacklist.IsBlacklisted(ctx,tokenStr) {
        return nil, errors.New("token is blacklisted")
    }
    RC_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    if s.blacklist.IsBlacklisted(ctx, RC_ID) {
        return nil, errors.New("token is blacklisted due to role change")
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
        s.blacklist.Add(ctx, tokenStr, expTime)
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

func (s *authServiceV2) InvalidateTokenOnRoleChange(ctx context.Context, userID int, userRole string ) error {
    Rc_ID := fmt.Sprintf("RC:%d:%s", userID, userRole)
    exp := time.Now().Add(s.config.RefreshTokenExp)
    s.blacklist.Add(ctx, Rc_ID, exp)
    return nil
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

    accessClaims, ok := access_claims.Claims.(jwt.MapClaims)
    if !ok {
        return errors.New("invalid access token claims format")
    }
    
    accessExp, ok := accessClaims["exp"].(float64)
    if !ok {
        return errors.New("invalid access token expiration")
    }
    access_expiresAt := time.Unix(int64(accessExp), 0)

    refreshClaims, ok := refresh_claims.Claims.(jwt.MapClaims)
    if !ok {
        return errors.New("invalid refresh token claims format")
    }
    
    refreshExp, ok := refreshClaims["exp"].(float64)
    if !ok {
        return errors.New("invalid refresh token expiration")
    }
    refresh_expiresAt := time.Unix(int64(refreshExp), 0)
    
    s.blacklist.Add(ctx, refreshToken, refresh_expiresAt)
    s.blacklist.Add(ctx, accessToken, access_expiresAt)
    return nil
}

func (s *authServiceV2) InitiatePasswordReset(ctx context.Context, email string) error {
    otp, err := GenerateOTP(6)
    if err != nil {
        return fmt.Errorf("failed to generate OTP: %w", err)
    }

    err = s.otpStore.StoreOTP(ctx, email, otp, 15*time.Minute)
    if err != nil {
        return fmt.Errorf("failed to store OTP: %w", err)
    }

    // In production, you would send this via email
    // For demonstration, we'll just log it
    fmt.Printf("Password reset OTP for %s: %s\n", email, otp)
    
    return nil
}

func (s *authServiceV2) VerifyPasswordResetOTP(ctx context.Context, email string, otp string) error {
    valid, err := s.otpStore.VerifyOTP(ctx, email, otp)
    if err != nil {
        return fmt.Errorf("failed to verify OTP: %w", err)
    }
    if !valid {
        return errors.New("invalid OTP")
    }

    err = s.otpStore.DeleteOTP(ctx, email)
    if err != nil {
        return fmt.Errorf("failed to delete OTP: %w", err)
    }

    return nil
}


