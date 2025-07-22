package authentication

import (
	"context"
	"time"
)

type AuthService interface {
    GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
    GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
    ValidateAccessToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error)
    ValidateRefreshToken(ctx context.Context, tokenStr string, fingerPRT string) (map[string]interface{}, error)
    Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error
}

type AuthServiceV2 interface {
	GenerateAccessToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
	GenerateRefreshToken(ctx context.Context, userID int, claims map[string]interface{}) (string, error)
	ValidateAccessToken(ctx context.Context, token string , fingerPRT string) (map[string]interface{}, error)
	ValidateRefreshToken(ctx context.Context, token string, fingerPRT string) (map[string]interface{}, error)
    CheckRoleAccess(ctx context.Context, userRole, path, method string) (bool, error)  
    CheckPolicyAccess(ctx context.Context, userID int, policy string) (bool, error) 
	Logout(ctx context.Context, refreshToken string, userID int, accessToken string) error
}

type Storage interface {
    AddRoleAccess(ctx context.Context, userRole, path, method string) error
	HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error)
    DeleteRoleAccess(ctx context.Context, userRole, path, method string) error
    AddPolicyAccess(ctx context.Context, userID int, policy string) error
    HasPolicyAccess(ctx context.Context, userID int, policy string) (bool, error)
    DeletePolicyAccess(ctx context.Context, userID int, policy string) error
}

type InMemory interface {
    Add(token string, expiresAt time.Time)
    IsBlacklisted(token string) bool
}

type RouteAccess interface {
    // Role-based access control
    AddRoleAccess(userRole, path, method string) error
    RemoveRoleAccess(userRole, path, method string) error
    HasRoleAccess(userRole, path, method string) bool
    
    // Policy-based access control
    AddPolicyAccess(userID int, policy string) error
    RemovePolicyAccess(userID int, policy string) error
    HasPolicyAccess(userID int, policy string) bool
}
