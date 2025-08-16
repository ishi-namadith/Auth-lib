package authentication

import (
	"context"
	"time"
)

type AuthService interface {
    GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
    GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
    ValidateAccessToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error)
    ValidateRefreshToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error)
    CreateRoleAccess(ctx context.Context, userRole, path, method string) error
    RemoveRoleAccess(ctx context.Context, userRole, path, method string) error
    HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error)
    CreatePolicyAccess(ctx context.Context, userRole, policy string) error
    RemovePolicyAccess(ctx context.Context, userRole, policy string) error
    HasPolicyAccess(ctx context.Context, userRole, policy string) (bool, error)
    InvalidateTokenOnRoleChange(ctx context.Context, userID int, userRole string) error
    Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error
    ReloadAllCaches(ctx context.Context) error
    InitiatePasswordReset(ctx context.Context, email string) error
    VerifyPasswordResetOTP(ctx context.Context, email string, otp string) error
}

type AuthServiceV2 interface {
	GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
	GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
	ValidateAccessToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error)
	ValidateRefreshToken(ctx context.Context, tokenStr string, userID int, userRole string, fingerPRT string) (map[string]interface{}, error)
    CreateRoleAccess(ctx context.Context, userRole, path, method string) error
    CheckRoleAccess(ctx context.Context, userRole, path, method string) (bool, error)  
    RemoveRoleAccess(ctx context.Context, userRole, path, method string) error
    CreatePolicyAccess(ctx context.Context, userID int, policy string) error
    CheckPolicyAccess(ctx context.Context, userID int, policy string) (bool, error)
    InvalidateTokenOnRoleChange(ctx context.Context, userID int, userRole string) error 
    RemovePolicyAccess(ctx context.Context, userID int, policy string) error
	Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error
    InitiatePasswordReset(ctx context.Context, email string) error
    VerifyPasswordResetOTP(ctx context.Context, email string, otp string) error
}

type Storage interface {
    AddRoleAccess(ctx context.Context, userRole, path, method string) error
    HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error)
    DeleteRoleAccess(ctx context.Context, userRole, path, method string) error
    AddRolePolicyAccess(ctx context.Context, userRole string, policy string) error
    DeleteRolePolicyAccess(ctx context.Context, userRole string, policy string) error
    AddPolicyAccess(ctx context.Context, userID int, policy string) error
    HasPolicyAccess(ctx context.Context, userID int, policy string) (bool, error)
    DeletePolicyAccess(ctx context.Context, userID int, policy string) error
    GetAllRoleAccess(ctx context.Context) ([]RoleAccessModel, error)
    GetAllPolicyAccess(ctx context.Context) ([]PolicyAccessModel, error)
}

type InMemory interface {
    Add(ctx context.Context, token string, expiresAt time.Time) error
    IsBlacklisted(ctx context.Context,token string) bool
}

type RouteAccess interface {
    AddRoleAccess(ctx context.Context, userRole, path, method string) error
    RemoveRoleAccess(ctx context.Context, userRole, path, method string) error
    HasRoleAccess(ctx context.Context, userRole, path, method string) bool
    AddPolicyAccess(ctx context.Context, userRole, policy string) error
    RemovePolicyAccess(ctx context.Context, userRole, policy string) error
    HasPolicyAccess(ctx context.Context, userRole, policy string) bool
    ReloadRoleAccess(ctx context.Context, roles []RoleAccessModel) error
    ReloadPolicyAccess(ctx context.Context, policies []PolicyAccessModel) error
    ClearAllCache(ctx context.Context) error
}

type OTPStore interface {
    StoreOTP(ctx context.Context, email string, otp string, expiry time.Duration) error
    VerifyOTP(ctx context.Context, email string, otp string) (bool, error)
    DeleteOTP(ctx context.Context, email string) error
}

type EmailService interface {
    SendOTP(to, otp string) error
}