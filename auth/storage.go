package authentication

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RoleAccessModel struct {
    UserRole string
    Path     string 
    Method   string
}

type PolicyAccessModel struct {
    UserRole string
    Policy   string
}

type PGStorage struct {
    db *pgxpool.Pool
}

func NewPGStorage(db *pgxpool.Pool) Storage {
    return &PGStorage{db: db}
}

func (s *PGStorage) AddRoleAccess(ctx context.Context, userRole, path, method string) error {
    query := `
        INSERT INTO role_auth (user_role, path, method)
        VALUES ($1, $2, $3)
    `
    _, err := s.db.Exec(ctx, query, userRole, path, method)
    return err
}

func (s *PGStorage) HasRoleAccess(ctx context.Context, userRole, path, method string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM role_auth
			WHERE user_role = $1 AND path = $2 AND method = $3
		)
	`
	var exists bool
	err := s.db.QueryRow(ctx, query, userRole, path, method).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check route access: %w", err)
	}
	return exists, nil
}

func (s *PGStorage) DeleteRoleAccess(ctx context.Context, userRole, path, method string) error {
    query := `
        DELETE FROM role_auth
        WHERE user_role = $1 AND path = $2 AND method = $3
    `
    _, err := s.db.Exec(ctx, query, userRole, path, method)
    return err
}

func (s *PGStorage) AddPolicyAccess(ctx context.Context, userID int, policy string) error {
    query := `
        INSERT INTO policy_auth (user_id, policy_name)
        VALUES ($1, $2)
    `
    _, err := s.db.Exec(ctx, query, userID, policy)
    return err
}

func (s *PGStorage) HasPolicyAccess(ctx context.Context, userID int, policy string) (bool, error) {
    query := `
        SELECT EXISTS (
            SELECT 1 FROM policy_auth
            WHERE user_id = $1 AND policy_name = $2
        )
    `
    var exists bool
    err := s.db.QueryRow(ctx, query, userID, policy).Scan(&exists)
    if err != nil {
        return false, fmt.Errorf("failed to check policy access: %w", err)
    }
    return exists, nil
}

func (s *PGStorage) DeletePolicyAccess(ctx context.Context, userID int, policy string) error {
    query := `
        DELETE FROM policy_auth
        WHERE user_id = $1 AND policy_name = $2
    `
    _, err := s.db.Exec(ctx, query, userID, policy)
    return err
}

