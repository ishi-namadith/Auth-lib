# Auth-lib

A production-ready Go authentication library with JWT tokens, role-based access control (RBAC), policy-based access control, and caching mechanisms.

## Features

- 🔐 **JWT Authentication**: Access and refresh tokens with SHA256 fingerprint verification
- 👥 **Role-Based Access Control (RBAC)**: Control access based on user roles and endpoints
- 📋 **Policy-Based Access Control**: Fine-grained permission management
- 🚫 **Token Blacklisting**: Secure token invalidation with automatic cleanup
- ⚡ **Dual Caching Strategy**: In-memory and Redis caching support
- 🗄️ **PostgreSQL Storage**: Persistent storage for roles and policies
- 🔒 **Thread-Safe Operations**: Concurrent-safe implementations
- 🌐 **Context-Aware**: Full context support with timeout handling
- 🔄 **Cache Management**: Dynamic cache reloading from database

## Architecture

```
Auth-lib/
├── auth/
│   ├── auth.go          // Core authentication services
│   ├── blacklist.go     // Token blacklisting (in-memory & Redis)
│   ├── config.go        // Configuration structs
│   ├── models.go        // Interfaces and data models
│   ├── routeAcess.go    // Access control caching
│   └── storage.go       // PostgreSQL storage operations
├── go.mod
└── README.md
```

## Installation

```bash
go get -u auth-lib
```

## Quick Start

### Basic Setup

```go
package main

import (
    "context"
    "log"
    "time"
    
    "auth-lib/auth"
    "github.com/jackc/pgx/v5/pgxpool"
)

func main() {
    // Configuration
    config := authentication.Config{
        AccessTokenSecret:  "your-super-secret-access-key",
        RefreshTokenSecret: "your-super-secret-refresh-key",
        AccessTokenExp:     15 * time.Minute,
        RefreshTokenExp:    24 * time.Hour,
    }

    // Database connection
    db, err := pgxpool.New(context.Background(), "postgres://user:password@localhost/authdb")
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()

    // Initialize components
    storage := authentication.NewPGStorage(db)
    blacklist := authentication.NewBlacklist()
    routeAccess := authentication.NewRouteAccessService()

    // Create auth service (with in-memory caching)
    authService := authentication.NewAuthService(config, storage, blacklist, routeAccess)

    // Load initial cache from database
    if err := authService.ReloadAllCaches(context.Background()); err != nil {
        log.Printf("Warning: Failed to load cache: %v", err)
    }

    log.Println("Auth service initialized successfully")
}
```

### Token Generation and Validation

```go
ctx := context.Background()

// Generate access token
token, err := authService.GenerateAccessToken(ctx, userID, map[string]interface{}{
    "role":       "admin",
    "fingerPRT":  "user-fingerprint-hash",
    "email":      "user@example.com",
})
if err != nil {
    log.Printf("Token generation failed: %v", err)
}

// Validate access token
claims, err := authService.ValidateAccessToken(ctx, token, userID, "admin", "user-fingerprint")
if err != nil {
    log.Printf("Token validation failed: %v", err)
}

// Generate refresh token
refreshToken, err := authService.GenerateRefreshToken(ctx, userID, map[string]interface{}{
    "role":       "admin",
    "fingerPRT":  "user-fingerprint-hash",
})
```

### Role-Based Access Control

```go
// Create role access
err := authService.CreateRoleAccess(ctx, "admin", "/api/users", "GET")
if err != nil {
    log.Printf("Failed to create role access: %v", err)
}

// Check role access
hasAccess, err := authService.HasRoleAccess(ctx, "admin", "/api/users", "GET")
if err != nil {
    log.Printf("Failed to check access: %v", err)
}

if hasAccess {
    log.Println("Access granted")
} else {
    log.Println("Access denied")
}

// Remove role access
err = authService.RemoveRoleAccess(ctx, "admin", "/api/users", "DELETE")
```

### Policy-Based Access Control

```go
// Create policy access
err := authService.CreatePolicyAccess(ctx, "admin", "user:read")
if err != nil {
    log.Printf("Failed to create policy: %v", err)
}

// Check policy access
hasPolicy, err := authService.HasPolicyAccess(ctx, "admin", "user:read")
if err != nil {
    log.Printf("Failed to check policy: %v", err)
}

// Remove policy access
err = authService.RemovePolicyAccess(ctx, "admin", "user:read")
```

### Token Management

```go
// Logout (blacklist tokens)
err := authService.Logout(ctx, refreshToken, userID, accessToken)
if err != nil {
    log.Printf("Logout failed: %v", err)
}

// Invalidate tokens on role change
err = authService.InvalidateTokenOnRoleChange(ctx, userID, "new-role")
if err != nil {
    log.Printf("Role change invalidation failed: %v", err)
}
```

### Cache Management

```go
// Reload all caches from database
err := authService.ReloadAllCaches(ctx)
if err != nil {
    log.Printf("Cache reload failed: %v", err)
}

// Reload specific caches
err = authService.ReloadRoleAccessCache(ctx)
err = authService.ReloadPolicyAccessCache(ctx)
```

## Two Service Variants

### AuthService (Recommended for High Performance)
- In-memory caching for lightning-fast access control checks
- Role-based policy access
- Best for applications requiring high-performance authorization

```go
authService := authentication.NewAuthService(config, storage, blacklist, routeAccess)
```

### AuthServiceV2 (Database-Only)
- Direct database operations without caching
- User-based policy access (by userID instead of role)
- Best for simple applications or memory-constrained environments

```go
authServiceV2 := authentication.NewAuthServiceWithoutInMemoryRA(config, storage, blacklist)

// User-based policy access
err := authServiceV2.CreatePolicyAccess(ctx, userID, "user:read")
hasAccess, err := authServiceV2.CheckPolicyAccess(ctx, userID, "user:read")
```

## Redis Support

### Redis Blacklist
```go
import "github.com/redis/go-redis/v9"

redisClient := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})

blacklist := authentication.NewBlacklistWithRedis(redisClient)
```

### Redis Route Access Cache
```go
routeAccess := authentication.NewRouteAccessServiceWithRedis(redisClient)
authService := authentication.NewAuthService(config, storage, blacklist, routeAccess)
```

## Database Schema

Create the following tables in your PostgreSQL database:

```sql
-- Role-based access control
CREATE TABLE role_auth (
    user_role VARCHAR(100) NOT NULL,
    path VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role, path, method)
);

-- Role-policy mapping (for AuthService)
CREATE TABLE rolepolicy_auth (
    user_role VARCHAR(100) NOT NULL,
    policy_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role, policy_name)
);

-- User-policy mapping (for AuthServiceV2)
CREATE TABLE policy_auth (
    user_id INTEGER NOT NULL,
    policy_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, policy_name)
);

-- Indexes for better performance
CREATE INDEX idx_role_auth_role ON role_auth(user_role);
CREATE INDEX idx_rolepolicy_auth_role ON rolepolicy_auth(user_role);
CREATE INDEX idx_policy_auth_user ON policy_auth(user_id);
```

## Configuration Options

```go
type Config struct {
    AccessTokenSecret  string        // Secret for signing access tokens
    RefreshTokenSecret string        // Secret for signing refresh tokens
    AccessTokenExp     time.Duration // Access token expiration (recommended: 15 minutes)
    RefreshTokenExp    time.Duration // Refresh token expiration (recommended: 24 hours)
}
```

## Security Features

### Fingerprint Verification
```go
// Tokens include SHA256 fingerprint verification
token, err := authService.GenerateAccessToken(ctx, userID, map[string]interface{}{
    "fingerPRT": "browser-fingerprint-hash",
})

// Validation requires matching fingerprint
claims, err := authService.ValidateAccessToken(ctx, token, userID, "admin", "browser-fingerprint-hash")
```

### Automatic Token Blacklisting
- Tokens are automatically blacklisted on fingerprint mismatch
- Role changes invalidate existing tokens
- Manual logout blacklists both access and refresh tokens
- Expired tokens are automatically cleaned up

### Thread-Safe Operations
- All operations are thread-safe and concurrent-ready
- Proper mutex usage in in-memory implementations
- No race conditions in cache operations

## Error Handling

The library provides detailed error messages for different scenarios:

```go
claims, err := authService.ValidateAccessToken(ctx, token, userID, role, fingerprint)
if err != nil {
    switch err.Error() {
    case "token is blacklisted":
        // Handle blacklisted token
    case "fingerprint mismatch":
        // Handle potential token hijacking
    case "invalid token":
        // Handle malformed or expired token
    default:
        // Handle other errors
    }
}
```

## HTTP Middleware Example

```go
func AuthMiddleware(authService authentication.AuthService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            if token == "" {
                http.Error(w, "Missing token", http.StatusUnauthorized)
                return
            }

            // Remove "Bearer " prefix
            if len(token) > 7 && token[:7] == "Bearer " {
                token = token[7:]
            }

            userID := getUserIDFromToken(token) // Your implementation
            userRole := getUserRoleFromToken(token) // Your implementation
            fingerprint := r.Header.Get("X-Fingerprint")

            _, err := authService.ValidateAccessToken(r.Context(), token, userID, userRole, fingerprint)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Check route access
            hasAccess, err := authService.HasRoleAccess(r.Context(), userRole, r.URL.Path, r.Method)
            if err != nil || !hasAccess {
                http.Error(w, "Access denied", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Best Practices

1. **Use HTTPS**: Always use HTTPS in production to protect tokens in transit
2. **Secure Storage**: Never store tokens in local storage; use secure HTTP-only cookies
3. **Short Expiration**: Keep access token expiration short (15 minutes recommended)
4. **Fingerprinting**: Implement browser fingerprinting for additional security
5. **Regular Cleanup**: Use the automatic cleanup features or implement periodic cleanup
6. **Error Handling**: Always handle errors appropriately and log security events
7. **Cache Management**: Reload caches after bulk permission changes

## Performance Tips

- Use `AuthService` for high-performance applications with frequent access checks
- Use `AuthServiceV2` for simple applications or when memory is constrained
- Consider Redis for distributed environments
- Implement connection pooling for database operations
- Monitor cache hit rates and adjust cache reload frequency

## Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/jackc/pgx/v5` - PostgreSQL driver
- `github.com/redis/go-redis/v9` - Redis client (optional)

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository.

Similar code found with 1 license type
