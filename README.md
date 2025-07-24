Project architecture

Auth-lib/
├── auth/
│   ├── auth.go          // Core authentication logic
│   ├── token.go         // Token generation and validation
│   ├── blacklist.go     // In-memory blacklist management
│   └── storage.go       // Storage interface and implementations
├── config/
│   └── config.go        // Configuration structs and defaults
├── models/
│   └── models.go        // Token and user models
├── examples/
│   └── main.go          // Example usage with net/http
├── go.mod
└── README.md

