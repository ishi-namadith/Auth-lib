# Auth-lib

A production-ready Go authentication library with JWT tokens, role-based access control (RBAC), policy-based access control, OTP-based password reset, and flexible caching/storage mechanisms.

---

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
- 📧 **Password Reset**: Secure OTP-based password reset with email support
- 🔄 **Multiple OTP Storage**: In-memory and Redis storage options for OTPs
- 📨 **Email Service**: Configurable SMTP email service with TLS support

---

## Architecture

```
Auth-lib/
├── auth/
│   ├── auth.go          // Core authentication services
│   ├── blacklist.go     // Token blacklisting (in-memory & Redis)
│   ├── config.go        // Configuration structs
│   ├── models.go        // Interfaces and data models
│   ├── otp.go           // OTP generation and storage (in-memory & Redis)
│   ├── pwreset.go       // Email service for password reset
│   ├── routeAcess.go    // Access control caching (in-memory & Redis)
│   └── storage.go       // PostgreSQL storage operations
├── go.mod
├── go.sum
└── README.md
```

---

## Installation

```bash
go get -u github.com/ishi-namadith/auth-lib
```

---

## Quick Start

### Basic Setup

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/ishi-namadith/auth-lib/auth"
    "github.com/redis/go-redis/v9"
    "github.com/jackc/pgx/v5/pgxpool"
)

func main() {
    // Redis client (for blacklist, route access, OTP)
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
        Password: "",
        DB: 0,
    })

    // Database connection (for persistent storage)
    db, err := pgxpool.New(context.Background(), "postgres://user:password@localhost/authdb")
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()

    // Configuration
    config := auth.Config{
        AccessTokenSecret:  "your-super-secret-access-key",
        RefreshTokenSecret: "your-super-secret-refresh-key",
        AccessTokenExp:     15 * time.Minute,
        RefreshTokenExp:    24 * time.Hour,
        EmailConfig: auth.EmailConfig{
            Host:     "smtp.gmail.com",
            Port:     587,
            Username: "your-email@gmail.com",
            Password: "your-app-password", // Use App Password for Gmail
            From:     "your-email@gmail.com",
            UseTLS:   true,
        },
    }

    // Initialize components
    storage := auth.NewPGStorage(db)
    blacklist := auth.NewBlacklistWithRedis(redisClient)
    routeAccess := auth.NewRouteAccessServiceWithRedis(redisClient)
    otpStore := auth.NewRedisOTPStore(redisClient)

    // Create auth service
    authService := auth.NewAuthService(config, storage, blacklist, routeAccess, otpStore)

    log.Println("Auth service initialized successfully")
}
```

---

## Token Generation and Validation

```go
ctx := context.Background()

// Generate access token
token, err := authService.GenerateAccessToken(ctx, userID, map[string]interface{}{
    "role":      "admin",
    "fingerPRT": "user-fingerprint-hash",
    "email":     "user@example.com",
})

// Validate access token
claims, err := authService.ValidateAccessToken(ctx, token, userID, "admin", "user-fingerprint-hash")

// Generate refresh token
refreshToken, err := authService.GenerateRefreshToken(ctx, userID, map[string]interface{}{
    "role":      "admin",
    "fingerPRT": "user-fingerprint-hash",
})
```

---

## Role-Based and Policy-Based Access Control

```go
// Create role access
err := authService.CreateRoleAccess(ctx, "admin", "/api/users", "GET")

// Check role access
hasAccess, err := authService.HasRoleAccess(ctx, "admin", "/api/users", "GET")

// Remove role access
err = authService.RemoveRoleAccess(ctx, "admin", "/api/users", "DELETE")

// Create policy access
err := authService.CreatePolicyAccess(ctx, "admin", "user:read")

// Check policy access
hasPolicy, err := authService.HasPolicyAccess(ctx, "admin", "user:read")

// Remove policy access
err = authService.RemovePolicyAccess(ctx, "admin", "user:read")
```

---

## Password Reset (OTP via Email)

```go
// Initiate password reset (sends OTP to email)
err := authService.InitiatePasswordReset(ctx, "user@example.com")

// Verify OTP (user submits OTP from email)
err := authService.VerifyPasswordResetOTP(ctx, "user@example.com", "123456")
```

---

## Redis/In-Memory Support

You can use in-memory or Redis for blacklist, route access, and OTP storage:

```go
// In-memory (single server)
blacklist := auth.NewBlacklist()
routeAccess := auth.NewRouteAccessService()
otpStore := auth.NewMemoryOTPStore()

// Redis (distributed)
blacklist := auth.NewBlacklistWithRedis(redisClient)
routeAccess := auth.NewRouteAccessServiceWithRedis(redisClient)
otpStore := auth.NewRedisOTPStore(redisClient)
```

---

## Database Schema (PostgreSQL)

```sql
-- Role-based access control
CREATE TABLE role_auth (
    user_role VARCHAR(100) NOT NULL,
    path VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role, path, method)
);

-- Role-policy mapping
CREATE TABLE rolepolicy_auth (
    user_role VARCHAR(100) NOT NULL,
    policy_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role, policy_name)
);

-- User-policy mapping
CREATE TABLE policy_auth (
    user_id INTEGER NOT NULL,
    policy_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, policy_name)
);

-- Indexes
CREATE INDEX idx_role_auth_role ON role_auth(user_role);
CREATE INDEX idx_rolepolicy_auth_role ON rolepolicy_auth(user_role);
CREATE INDEX idx_policy_auth_user ON policy_auth(user_id);
```

---

## Configuration Options

```go
type Config struct {
    AccessTokenSecret  string
    RefreshTokenSecret string
    AccessTokenExp     time.Duration
    RefreshTokenExp    time.Duration
    EmailConfig        EmailConfig
}

type EmailConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    ReplyTo  string
    UseTLS   bool
}
```

---

## Security Features

- **Fingerprint Verification**: SHA256 hash of device/browser fingerprint in tokens
- **Automatic Blacklisting**: On fingerprint mismatch, logout, or role change
- **Thread-Safe**: Mutexes for in-memory, atomic Redis operations
- **Context Support**: All operations accept `context.Context`
- **Short Expiry**: Recommended 15m access, 24h refresh
- **TLS Email**: Secure SMTP for OTP delivery

---

## Error Handling

```go
claims, err := authService.ValidateAccessToken(ctx, token, userID, role, fingerprint)
if err != nil {
    switch err.Error() {
    case "token is blacklisted":
        // Handle blacklisted token
    case "fingerprint mismatch":
        // Handle hijacking attempt
    case "invalid token":
        // Handle expired/malformed token
    default:
        // Other errors
    }
}
```

---

## HTTP Middleware Example

```go
func AuthMiddleware(authService auth.AuthService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            if token == "" {
                http.Error(w, "Missing token", http.StatusUnauthorized)
                return
            }
            token = strings.TrimPrefix(token, "Bearer ")
            fingerprint := r.Header.Get("X-Fingerprint")
            claims, err := authService.ValidateAccessToken(r.Context(), token, getUserID(token), getRole(token), fingerprint)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

---

## Best Practices

- Use HTTPS in production
- Store tokens in HTTP-only cookies
- Implement rate limiting for password reset/OTP
- Use short-lived access tokens
- Reload caches after bulk permission changes
- Use TLS for email delivery

---

## Performance Tips

- Use Redis for distributed deployments
- Use in-memory for single-server, high-speed access
- Monitor cache hit rates
- Use connection pooling for PostgreSQL

---

## Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/redis/go-redis/v9` - Redis client
- `github.com/jackc/pgx/v5` - PostgreSQL driver

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

## Support

For issues and questions, please open an issue on the GitHub repository.

---

## License

MIT License

---

## Authors

- Ishi Namadith

---

## Acknowledgments

- JWT implementation based on `golang-jwt/jwt`
- Redis support via `go-redis/redis`
- PostgreSQL integration with `jackc/pgx`