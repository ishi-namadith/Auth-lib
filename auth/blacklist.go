package auth

import (
	"sync"
	"time"
)

type Blacklist struct {
	tokens map[string]time.Time
	mu sync.RWMutex
}

func NewBlacklist() InMemory {
	return &Blacklist{
		tokens: make(map[string]time.Time),
	}
}

func (b *Blacklist) Add(token string, expiresAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = expiresAt
	go b.Cleanup(token, expiresAt)
}

func (b *Blacklist) Cleanup(token string, expiresAt time.Time) {
    time.Sleep(time.Until(expiresAt))
    b.mu.Lock()
    delete(b.tokens, token)
    b.mu.Unlock()
}

// used to check if a token is blacklisted
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


