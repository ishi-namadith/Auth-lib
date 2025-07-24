package authentication

import (
    "context"
    "fmt"
    "sync"
    "github.com/redis/go-redis/v9"
)

type RouteAccessService struct {
    roleTokens   map[RoleModel]struct{}
    policyTokens map[PolicyModel]struct{}
    mu           sync.RWMutex
}

type RouteAccessServiceWithRedis struct {
    client *redis.Client
}

type RoleModel struct {
    UserRole string
    Path     string
    Method   string
}

type PolicyModel struct {
    UserRole string
    Policy string
}

// In-memory approach
func NewRouteAccessService() RouteAccess {
    return &RouteAccessService{
        roleTokens:   make(map[RoleModel]struct{}),
        policyTokens: make(map[PolicyModel]struct{}),
    }
}

// Redis approach
func NewRouteAccessServiceWithRedis(redisClient *redis.Client) RouteAccess {
    return &RouteAccessServiceWithRedis{
        client: redisClient,
    }
}

// In-memory role-based methods
func (s *RouteAccessService) AddRoleAccess(ctx context.Context, userRole, path, method string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.roleTokens[RoleModel{UserRole: userRole, Path: path, Method: method}] = struct{}{}
    return nil
}

func (s *RouteAccessService) RemoveRoleAccess(ctx context.Context, userRole, path, method string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.roleTokens, RoleModel{UserRole: userRole, Path: path, Method: method})
    return nil
}

func (s *RouteAccessService) HasRoleAccess(ctx context.Context, userRole, path, method string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    _, exists := s.roleTokens[RoleModel{UserRole: userRole, Path: path, Method: method}]
    return exists
}

// In-memory policy-based methods
func (s *RouteAccessService) AddPolicyAccess(ctx context.Context, userRole, policy string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.policyTokens[PolicyModel{UserRole: userRole, Policy: policy}] = struct{}{}
    return nil
}

func (s *RouteAccessService) RemovePolicyAccess(ctx context.Context, userRole, policy string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.policyTokens, PolicyModel{UserRole: userRole, Policy: policy})
    return nil
}

func (s *RouteAccessService) HasPolicyAccess(ctx context.Context, userRole string, policy string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    _, exists := s.policyTokens[PolicyModel{UserRole: userRole, Policy: policy}]
    return exists
}

func (s *RouteAccessService) ReloadRoleAccess(ctx context.Context, roles []RoleAccessModel) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.roleTokens = make(map[RoleModel]struct{})

    for _, role := range roles {
        s.roleTokens[RoleModel(role)] = struct{}{}
    }
    return nil
}

func (s *RouteAccessService) ReloadPolicyAccess(ctx context.Context, policies []PolicyAccessModel) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.policyTokens = make(map[PolicyModel]struct{})

    for _, policy := range policies {
        s.policyTokens[PolicyModel(policy)] = struct{}{}
    }
    
    return nil
}

func (s *RouteAccessService) ClearAllCache(ctx context.Context) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.roleTokens = make(map[RoleModel]struct{})
    s.policyTokens = make(map[PolicyModel]struct{})
    
    return nil
}

// Redis role-based methods
func (r *RouteAccessServiceWithRedis) AddRoleAccess(ctx context.Context,userRole, path, method string) error {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    return r.client.Set(ctx, key, "allowed", 0).Err()
}

func (r *RouteAccessServiceWithRedis) RemoveRoleAccess(ctx context.Context, userRole, path, method string) error {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    return r.client.Del(ctx, key).Err()
}

func (r *RouteAccessServiceWithRedis) HasRoleAccess(ctx context.Context, userRole, path, method string) bool {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    result := r.client.Exists(ctx, key)
    return result.Val() > 0
}

// Redis policy-based methods
func (r *RouteAccessServiceWithRedis) AddPolicyAccess(ctx context.Context, userRole, policy string) error {
    key := fmt.Sprintf("policy_access:%s:%s", userRole, policy)
    return r.client.Set(ctx, key, "allowed", 0).Err()
}

func (r *RouteAccessServiceWithRedis) RemovePolicyAccess(ctx context.Context, userRole, policy string) error {
    key := fmt.Sprintf("policy_access:%s:%s", userRole, policy)
    return r.client.Del(ctx, key).Err()
}

func (r *RouteAccessServiceWithRedis) HasPolicyAccess(ctx context.Context, userRole, policy string) bool {
    key := fmt.Sprintf("policy_access:%s:%s", userRole, policy)
    result := r.client.Exists(ctx, key)
    return result.Val() > 0
}

func (r *RouteAccessServiceWithRedis) ReloadRoleAccess(ctx context.Context, roles []RoleAccessModel) error {
    // Clear existing keys
    pattern := "role_access:*"
    keys := r.client.Keys(ctx, pattern)
    if keys.Val() != nil && len(keys.Val()) > 0 {
        r.client.Del(ctx, keys.Val()...)
    }

    for _, role := range roles {
        key := fmt.Sprintf("role_access:%s:%s:%s", role.UserRole, role.Path, role.Method)
        if err := r.client.Set(ctx, key, "allowed", 0).Err(); err != nil {
            return fmt.Errorf("failed to reload role access: %w", err)
        }
    }
    
    return nil
}

func (r *RouteAccessServiceWithRedis) ReloadPolicyAccess(ctx context.Context, policies []PolicyAccessModel) error {
    // Clear existing keys
    pattern := "policy_access:*"
    keys := r.client.Keys(ctx, pattern)
    if keys.Val() != nil && len(keys.Val()) > 0 {
        r.client.Del(ctx, keys.Val()...)
    }
    
    // Load new data
    for _, policy := range policies {
        key := fmt.Sprintf("policy_access:%s:%s", policy.UserRole, policy.Policy)
        if err := r.client.Set(ctx, key, "allowed", 0).Err(); err != nil {
            return fmt.Errorf("failed to reload policy access: %w", err)
        }
    }
    
    return nil
}

func (r *RouteAccessServiceWithRedis) ClearAllCache(ctx context.Context) error {
    rolePattern := "role_access:*"
    policyPattern := "policy_access:*"

    roleKeys := r.client.Keys(ctx, rolePattern)
    policyKeys := r.client.Keys(ctx, policyPattern)
    
    allKeys := append(roleKeys.Val(), policyKeys.Val()...)
    if len(allKeys) > 0 {
        return r.client.Del(ctx, allKeys...).Err()
    }
    
    return nil
}