package authentication

import (
	"time"
)

type EmailConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    // Optional settings
    ReplyTo  string
    UseTLS   bool
}

type Config struct {
    AccessTokenSecret  string 
    RefreshTokenSecret string 
    AccessTokenExp     time.Duration 	
    RefreshTokenExp    time.Duration
    EmailConfig       EmailConfig
}