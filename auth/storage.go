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

func (s *PGStorage) GetAllRoleAccess(ctx context.Context) ([]RoleAccessModel, error) {
    query := `
        SELECT user_role, path, method FROM role_auth
    `
    rows, err := s.db.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to get role access: %w", err)
    }
    defer rows.Close()
    
    var roleAccesses []RoleAccessModel
    for rows.Next() {
        var role RoleAccessModel
        if err := rows.Scan(&role.UserRole, &role.Path, &role.Method); err != nil {
            return nil, fmt.Errorf("failed to scan role access: %w", err)
        }
        roleAccesses = append(roleAccesses, role)
    }
    
    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating role access rows: %w", err)
    }
    
    return roleAccesses, nil
}

func (s *PGStorage) DeleteRoleAccess(ctx context.Context, userRole, path, method string) error {
    query := `
        DELETE FROM role_auth
        WHERE user_role = $1 AND path = $2 AND method = $3
    `
    _, err := s.db.Exec(ctx, query, userRole, path, method)
    return err
}

func (s *PGStorage) AddRolePolicyAccess(ctx context.Context, userRole string, policy string) error {
    query := `
        INSERT INTO rolepolicy_auth (user_role, policy_name)
        VALUES ($1, $2)
    `
    _, err := s.db.Exec(ctx, query, userRole, policy)
    return err
}

func (s *PGStorage) DeleteRolePolicyAccess(ctx context.Context, userRole string, policy string) error {
    query := `
        DELETE FROM rolepolicy_auth
        WHERE user_role = $1 AND policy_name = $2
    `
    _, err := s.db.Exec(ctx, query, userRole, policy)
    return err
}

func (s *PGStorage) GetAllPolicyAccess(ctx context.Context) ([]PolicyAccessModel, error) {
    query := `
        SELECT user_role, policy_name FROM rolepolicy_auth
    `
    rows, err := s.db.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to get policy access: %w", err)
    }
    defer rows.Close()

    var policyAccesses []PolicyAccessModel
    for rows.Next() {
        var policy PolicyAccessModel
        if err := rows.Scan(&policy.UserRole, &policy.Policy); err != nil {
            return nil, fmt.Errorf("failed to scan policy access: %w", err)
        }
        policyAccesses = append(policyAccesses, policy)
    }
    
    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating policy access rows: %w", err)
    }
    
    return policyAccesses, nil
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

