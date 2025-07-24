package authentication

import (
    "context"
    "sync"
    "time"
    "errors"
    "github.com/redis/go-redis/v9"
)

type Blacklist struct {
    tokens map[string]time.Time
    mu sync.RWMutex
}

type BlacklistWithRedis struct {
    client *redis.Client
}

func NewBlacklist() InMemory {
    return &Blacklist{
        tokens: make(map[string]time.Time),
    }
}

func NewBlacklistWithRedis(redisClient *redis.Client) InMemory {
    return &BlacklistWithRedis{
        client: redisClient,
    }
}

func (b *Blacklist) Add(ctx context.Context, token string, expiresAt time.Time) error {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.tokens[token] = expiresAt
    return nil
}

func (b *Blacklist) IsBlacklisted(ctx context.Context,token string) bool {
    b.mu.RLock()
    expiration, exists := b.tokens[token]
    b.mu.RUnlock()
    
    if !exists {
        return false
    }
    
    if time.Now().After(expiration) {
        b.mu.Lock()
        if exp, exists := b.tokens[token]; exists && time.Now().After(exp) {
            delete(b.tokens, token)
        }
        b.mu.Unlock()
        return false
    }
    return true
}

func (r *BlacklistWithRedis) Add(ctx context.Context,token string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        return errors.New("token already expired")
    }
    return r.client.Set(ctx, "blacklist:"+token, "blacklisted", ttl).Err()
}

func (r *BlacklistWithRedis) IsBlacklisted(ctx context.Context, token string) bool {
    result := r.client.Exists(ctx, "blacklist:"+token)
    return result.Val() > 0
}