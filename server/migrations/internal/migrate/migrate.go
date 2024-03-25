package migrate

import (
	"database/sql"
	"embed"
	"io/fs"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// Migrations contains embedded migration files for use with goose.
//
//go:embed migrations
var Migrations embed.FS

// Migrate runs the migrations from the specified path using the provided DSN.
// It sets up a connection to a Postgres database, applies the migrations, and then closes the connection.
//
// Parameters:
//   - dsn: The data source name (DSN) specifying the database connection details.
//   - path: The file system abstraction representing the directory containing migration files.
//
// Returns:
//   - error: An error, if any occurred during the migration process.
func Migrate(dsn string, path fs.FS) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	defer db.Close()

	goose.SetBaseFS(path)
	return goose.Up(db, "migrations")
}
