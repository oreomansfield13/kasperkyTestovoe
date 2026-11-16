package repository

import (
	"fmt"
	"os"
	"strings" // Добавлен импорт для работы со строкой подключения

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

func RunMigrations(databaseURL string) error {
	// Используем os.DirFS, чтобы читать миграции из папки рядом с бинарником
	d, err := iofs.New(os.DirFS("migrations"), ".")
	if err != nil {
		return fmt.Errorf("failed to create iofs source: %w", err)
	}

	// Очищаем строку от префикса postgres:// или postgresql://
	cleanURL := strings.TrimPrefix(databaseURL, "postgres://")
	cleanURL = strings.TrimPrefix(cleanURL, "postgresql://")

	// Собираем правильный URL для драйвера pgx5
	migrationURL := "pgx5://" + cleanURL

	m, err := migrate.NewWithSourceInstance("iofs", d, migrationURL)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}
