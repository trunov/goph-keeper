package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
	log "github.com/sirupsen/logrus"
)

type Credential struct {
	ID         int    `json:"id"`
	UserID     int64  `-`
	DataType   int    `json:"data_type"`
	BinaryData []byte `json:"binary_data"`
	MetaInfo   string `json:"meta_info"`
}

type dbStorage struct {
	dbpool *pgxpool.Pool
}

func NewDBStorage(conn *pgxpool.Pool) *dbStorage {
	return &dbStorage{dbpool: conn}
}

func (s *dbStorage) StoreData(ctx context.Context, userID int64, data_type int, binary_data []byte, meta_info string) (*Credential, error) {
	query := `
		INSERT INTO credentials (user_id, data_type, binary_data, meta_info)
		VALUES ($1, $2, $3, $4)
		RETURNING id, data_type, binary_data, meta_info
	`

	var cred Credential
	err := s.dbpool.QueryRow(ctx, query, userID, data_type, binary_data, meta_info).Scan(&cred.ID, &cred.DataType, &cred.BinaryData, &cred.MetaInfo)
	if err != nil {
		log.Errorf("error inserting data into credentials table: %v", err)
		return nil, err
	}

	cred.UserID = userID

	return &cred, nil
}

func (s *dbStorage) RetrieveCredentials(ctx context.Context, userID int64) ([]Credential, error) {
	query := `
		SELECT data_type, binary_data, meta_info
		FROM credentials
		WHERE user_id = $1
	`

	rows, err := s.dbpool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("error querying credentials from database: %v", err)
	}
	defer rows.Close()

	var credentials []Credential
	for rows.Next() {
		var c Credential
		err := rows.Scan(&c.DataType, &c.BinaryData, &c.MetaInfo)
		if err != nil {
			return nil, fmt.Errorf("error scanning credentials row: %v", err)
		}
		credentials = append(credentials, c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials rows: %v", err)
	}

	return credentials, nil
}
