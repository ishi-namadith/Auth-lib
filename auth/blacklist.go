package authentication

import (
    "context"
    "sync"
    "time"
    "github.com/redis/go-redis/v9"
)

type Blacklist struct {
    tokens map[string]time.Time
    mu sync.RWMutex
}

type BlacklistWithRedis struct {
    client *redis.Client
    ctx    context.Context
}

func NewBlacklist() InMemory {
    return &Blacklist{
        tokens: make(map[string]time.Time),
    }
}

func NewBlacklistWithRedis(redisClient *redis.Client) InMemory {
    return &BlacklistWithRedis{
        client: redisClient,
        ctx:    context.Background(),
    }
}

func (b *Blacklist) Add(token string, expiresAt time.Time) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.tokens[token] = expiresAt
}

func (b *Blacklist) IsBlacklisted(token string) bool {
    b.mu.RLock()
    defer b.mu.RUnlock()
    expiration, exists := b.tokens[token]
    if !exists {
        return false
    }
    if time.Now().After(expiration) {
        delete(b.tokens, token)
        return false
    }
    return true
}

func (r *BlacklistWithRedis) Add(token string, expiresAt time.Time) {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        return 
    }
    r.client.Set(r.ctx, "blacklist:"+token, "blacklisted", ttl)
}

func (r *BlacklistWithRedis) IsBlacklisted(token string) bool {
    result := r.client.Exists(r.ctx, "blacklist:"+token)
    return result.Val() > 0
}