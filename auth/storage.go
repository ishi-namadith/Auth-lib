package auth

import (
    "context"
    "database/sql"
    "fmt"
    "time"
)

type PGStorage struct {
    db *sql.DB
}

type MySQLStorage struct {
    db *sql.DB
}

func NewDBStorage(database, dsn string) (Storage, error) {
    db, err := sql.Open(database, dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    // Verify connection
    if err := db.Ping(); err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    switch database {
    case "postgres":
        return &PGStorage{db: db}, nil
    case "mysql":
        return &MySQLStorage{db: db}, nil
    default:
        db.Close()
        return nil, fmt.Errorf("unsupported database: %s", database)
    }
}

func (s *PGStorage) SaveRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
    query := `INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`
    _, err := s.db.ExecContext(ctx, query, userID, token, expiresAt)
    return err
}

func (s *PGStorage) DeleteRefreshToken(ctx context.Context, token string) error {
    query := `DELETE FROM refresh_tokens WHERE token = $1`
    _, err := s.db.ExecContext(ctx, query, token)
    return err
}

func (s *PGStorage) HasRouteAccess(ctx context.Context, user_role, path, method string) (bool, error) {
    query := `
        SELECT EXISTS (
            SELECT 1
            FROM user_routes
            WHERE user_role = $1
            AND path = $2
            AND method = $3
        )`
    var hasAccess bool
    err := s.db.QueryRowContext(ctx, query, user_role, path, method).Scan(&hasAccess)
    return hasAccess, err
}

// MySQLStorage implements Storage interface for MySQL database
func (s *MySQLStorage) SaveRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
    query := `INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`
    _, err := s.db.ExecContext(ctx, query, userID, token, expiresAt)
    return err
}

func (s *MySQLStorage) DeleteRefreshToken(ctx context.Context, token string) error {
    query := `DELETE FROM refresh_tokens WHERE token = ?`
    _, err := s.db.ExecContext(ctx, query, token)
    return err
}

func (s *MySQLStorage) HasRouteAccess(ctx context.Context, user_role, path, method string) (bool, error) {
    query := `
        SELECT EXISTS (
            SELECT 1
            FROM user_routes
            WHERE user_role = ?
            AND path = ?
            AND method = ?
        )`
    var hasAccess bool
    err := s.db.QueryRowContext(ctx, query, user_role, path, method).Scan(&hasAccess)
    return hasAccess, err
}