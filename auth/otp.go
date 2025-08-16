package authentication

import (
    "context"
    "crypto/rand"
    "errors"
    "fmt"
    "sync"
    "time"
    
    "github.com/redis/go-redis/v9"
)

// in memory store
type otpData struct {
    code      string
    expiresAt time.Time
}

type MemoryOTPStore struct {
    otps map[string]otpData
    mu   sync.RWMutex
}

// Redis OTP store
type RedisOTPStore struct {
    client *redis.Client
}

func NewMemoryOTPStore() OTPStore {
    return &MemoryOTPStore{
        otps: make(map[string]otpData),
    }
}

func NewRedisOTPStore(redisClient *redis.Client) OTPStore {
    return &RedisOTPStore{
        client: redisClient,
    }
}

// In-memory implementations
func (s *MemoryOTPStore) StoreOTP(ctx context.Context, email string, otp string, expiry time.Duration) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.otps[email] = otpData{
        code:      otp,
        expiresAt: time.Now().Add(expiry),
    }
    return nil
}

func (s *MemoryOTPStore) VerifyOTP(ctx context.Context, email string, otp string) (bool, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    data, exists := s.otps[email]
    if !exists {
        return false, errors.New("no OTP found for email")
    }

    if time.Now().After(data.expiresAt) {
        s.mu.RUnlock()
        s.DeleteOTP(ctx, email)
        return false, errors.New("OTP expired")
    }

    return data.code == otp, nil
}

func (s *MemoryOTPStore) DeleteOTP(ctx context.Context, email string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    delete(s.otps, email)
    return nil
}

// Redis implementations
func (s *RedisOTPStore) StoreOTP(ctx context.Context, email string, otp string, expiry time.Duration) error {
    key := fmt.Sprintf("otp:%s", email)
    return s.client.Set(ctx, key, otp, expiry).Err()
}

func (s *RedisOTPStore) VerifyOTP(ctx context.Context, email string, otp string) (bool, error) {
    key := fmt.Sprintf("otp:%s", email)
    storedOTP, err := s.client.Get(ctx, key).Result()
    if err == redis.Nil {
        return false, errors.New("no OTP found for email")
    }
    if err != nil {
        return false, err
    }

    return storedOTP == otp, nil
}

func (s *RedisOTPStore) DeleteOTP(ctx context.Context, email string) error {
    key := fmt.Sprintf("otp:%s", email)
    return s.client.Del(ctx, key).Err()
}

func GenerateOTP(length int) (string, error) {
    const digits = "0123456789"
    bytes := make([]byte, length)
    _, err := rand.Read(bytes)
    if err != nil {
        return "", err
    }
    for i, b := range bytes {
        bytes[i] = digits[int(b)%len(digits)]
    }
    return string(bytes), nil
}

