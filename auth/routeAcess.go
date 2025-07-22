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
    ctx    context.Context
}

type RoleModel struct {
    UserRole string
    Path     string
    Method   string
}

type PolicyModel struct {
    UserID int
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
        ctx:    context.Background(),
    }
}

// In-memory role-based methods
func (s *RouteAccessService) AddRoleAccess(userRole, path, method string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.roleTokens[RoleModel{UserRole: userRole, Path: path, Method: method}] = struct{}{}
    return nil
}

func (s *RouteAccessService) RemoveRoleAccess(userRole, path, method string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.roleTokens, RoleModel{UserRole: userRole, Path: path, Method: method})
    return nil
}

func (s *RouteAccessService) HasRoleAccess(userRole, path, method string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    _, exists := s.roleTokens[RoleModel{UserRole: userRole, Path: path, Method: method}]
    return exists
}

// In-memory policy-based methods
func (s *RouteAccessService) AddPolicyAccess(userID int, policy string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.policyTokens[PolicyModel{UserID: userID, Policy: policy}] = struct{}{}
    return nil
}

func (s *RouteAccessService) RemovePolicyAccess(userID int, policy string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.policyTokens, PolicyModel{UserID: userID, Policy: policy})
    return nil
}

func (s *RouteAccessService) HasPolicyAccess(userID int, policy string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    _, exists := s.policyTokens[PolicyModel{UserID: userID, Policy: policy}]
    return exists
}

// Redis role-based methods
func (r *RouteAccessServiceWithRedis) AddRoleAccess(userRole, path, method string) error {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    return r.client.Set(r.ctx, key, "allowed", 0).Err()
}

func (r *RouteAccessServiceWithRedis) RemoveRoleAccess(userRole, path, method string) error {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    return r.client.Del(r.ctx, key).Err()
}

func (r *RouteAccessServiceWithRedis) HasRoleAccess(userRole, path, method string) bool {
    key := fmt.Sprintf("role_access:%s:%s:%s", userRole, path, method)
    result := r.client.Exists(r.ctx, key)
    return result.Val() > 0
}

// Redis policy-based methods
func (r *RouteAccessServiceWithRedis) AddPolicyAccess(userID int, policy string) error {
    key := fmt.Sprintf("policy_access:%d:%s", userID, policy)
    return r.client.Set(r.ctx, key, "allowed", 0).Err()
}

func (r *RouteAccessServiceWithRedis) RemovePolicyAccess(userID int, policy string) error {
    key := fmt.Sprintf("policy_access:%d:%s", userID, policy)
    return r.client.Del(r.ctx, key).Err()
}

func (r *RouteAccessServiceWithRedis) HasPolicyAccess(userID int, policy string) bool {
    key := fmt.Sprintf("policy_access:%d:%s", userID, policy)
    result := r.client.Exists(r.ctx, key)
    return result.Val() > 0
}