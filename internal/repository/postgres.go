package repository

import (
	"context"
	"errors"
	"fmt"
	"threat-exchange/internal/model"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresRepo struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(ctx context.Context, dsn string) (ThreatRepository, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	return &postgresRepo{pool: pool}, nil
}

func (r *postgresRepo) Create(ctx context.Context, t *model.Threat) error {
	query := `
		INSERT INTO threats (md5, sha256, name, threat_type, severity, description, file_size, file_type, tags, ref, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.pool.Exec(ctx, query, t.MD5, t.SHA256, t.Name, t.ThreatType, t.Severity, t.Description, t.FileSize, t.FileType, t.Tags, t.References, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Код ошибки UNIQUE VIOLATION
			return model.ErrConflict
		}
		return fmt.Errorf("failed to insert threat: %w", err)
	}
	return nil
}

func (r *postgresRepo) GetByMD5(ctx context.Context, md5 string) (*model.Threat, error) {
	query := `SELECT md5, sha256, name, threat_type, severity, description, file_size, file_type, tags, ref, created_at, updated_at FROM threats WHERE md5 = $1`
	var t model.Threat
	err := r.pool.QueryRow(ctx, query, md5).Scan(&t.MD5, &t.SHA256, &t.Name, &t.ThreatType, &t.Severity, &t.Description, &t.FileSize, &t.FileType, &t.Tags, &t.References, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get threat: %w", err)
	}
	return &t, nil
}

func (r *postgresRepo) Update(ctx context.Context, t *model.Threat) error {
	query := `UPDATE threats SET sha256=$1, name=$2, threat_type=$3, severity=$4, description=$5, file_size=$6, file_type=$7, tags=$8, ref=$9, updated_at=$10 WHERE md5=$11`
	cmdTag, err := r.pool.Exec(ctx, query, t.SHA256, t.Name, t.ThreatType, t.Severity, t.Description, t.FileSize, t.FileType, t.Tags, t.References, t.UpdatedAt, t.MD5)
	if err != nil {
		return fmt.Errorf("failed to update threat: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}
