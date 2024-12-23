package psql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type TokenPair struct {
	UserID        uuid.UUID `db:"user_id"`
	RefreshHash   string    `db:"refresh_hash"`
	AccessTokenID string    `db:"access_token_id"`
	CreatedAt     time.Time `db:"created_at"`
	ClientIP      string    `db:"client_ip"`
}

type Storage struct {
	db *sql.DB
}

// New создает новое подключение к PostgreSQL по переданному DSN (storagePath).
func New(storagePath string) (*Storage, error) {
	const operation = "storage.postgresql.New"

	if storagePath == "" {
		return nil, fmt.Errorf("%s: storagePath is empty", operation)
	}

	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: open connection: %w", operation, err)
	}

	query := `
		CREATE TABLE IF NOT EXISTS token_pairs (
			user_id UUID NOT NULL,
			refresh_hash TEXT NOT NULL,
			access_token_id TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL,
			client_ip TEXT NOT NULL
		)`
	if _, err := db.Exec(query); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: create table: %w", operation, err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: ping database: %w", operation, err)
	}

	return &Storage{db: db}, nil
}

// SaveTokenPair сохраняет запись о токенах (refresh hash + access_id) в базе данных.
func (s *Storage) SaveTokenPair(tp TokenPair) error {
	query := `INSERT INTO token_pairs (user_id, refresh_hash, access_token_id, created_at, client_ip)
              VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Exec(query, tp.UserID, tp.RefreshHash, tp.AccessTokenID, tp.CreatedAt, tp.ClientIP)
	if err != nil {
		return fmt.Errorf("SaveTokenPair: %w", err)
	}
	return nil
}

// GetTokenPairByAccessID возвращает TokenPair по access_token_id.
func (s *Storage) GetTokenPairByAccessID(accessID string) (*TokenPair, error) {
	query := `SELECT user_id, refresh_hash, access_token_id, created_at, client_ip
              FROM token_pairs WHERE access_token_id = $1`
	row := s.db.QueryRow(query, accessID)

	var tp TokenPair
	if err := row.Scan(&tp.UserID, &tp.RefreshHash, &tp.AccessTokenID, &tp.CreatedAt, &tp.ClientIP); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("GetTokenPairByAccessID: token pair not found")
		}
		return nil, fmt.Errorf("GetTokenPairByAccessID: %w", err)
	}
	return &tp, nil
}

// DeleteTokenPair удаляет запись о токенах по access_token_id.
func (s *Storage) DeleteTokenPair(accessID string) error {
	query := `DELETE FROM token_pairs WHERE access_token_id = $1`
	_, err := s.db.Exec(query, accessID)
	if err != nil {
		return fmt.Errorf("DeleteTokenPair: %w", err)
	}
	return nil
}
