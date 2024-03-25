package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/trunov/goph-keeper/server/auth/internal/domain/models"
)

var ErrUserNotFound = errors.New("user not found")

// Proposal: to create errors so we could compare them in server as Error.is()

type dbStorage struct {
	dbpool *pgxpool.Pool
}

func NewDBStorage(conn *pgxpool.Pool) *dbStorage {
	return &dbStorage{dbpool: conn}
}

func (s *dbStorage) RegisterUser(ctx context.Context, email, password string) (int64, error) {
	var userID int64

	err := s.dbpool.QueryRow(ctx, "INSERT INTO users (email, password) values ($1, $2) RETURNING id", email, password).Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, fmt.Errorf("unique constraint violation: %w", err)
		}
		return 0, fmt.Errorf("error executing query: %w", err)
	}

	return userID, nil
}

func (s *dbStorage) FindUser(ctx context.Context, email string) (models.User, error) {
	var user models.User

	query := "SELECT id, email, password FROM users WHERE email = $1"
	row := s.dbpool.QueryRow(ctx, query, email)

	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, ErrUserNotFound
		}
		return models.User{}, err
	}

	return user, nil
}
