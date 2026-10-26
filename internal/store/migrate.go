package store

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Registers the postgres driver that NewWithSourceInstance resolves from
	// the postgres:// scheme in DATABASE_URL.
	_ "github.com/golang-migrate/migrate/v4/database/postgres"

	// Registers the sqlite driver resolved from the sqlite:// scheme. It is
	// built on modernc.org/sqlite, the pure-Go driver, so CGO stays off.
	_ "github.com/golang-migrate/migrate/v4/database/sqlite"
)

// Two migration sets live side by side, one per SQL dialect:
//
//	migrations/postgres/  the production schema
//	migrations/sqlite/    the same tables and columns, phrased for SQLite
//
// They share version numbers and file basenames — migration N is applied
// under whichever directory the URL selects — and a test in this package
// asserts the two dialects end up with the same table and column sets, so a
// migration added for one backend cannot silently skip the other.
//
//go:embed migrations/postgres/*.sql migrations/sqlite/*.sql
var migrationsFS embed.FS

// SQLiteURLPrefix is the DATABASE_URL scheme that selects the SQLite store.
// A URL like sqlite:///home/me/history.db opens (and migrates) that file.
const SQLiteURLPrefix = "sqlite://"

// IsSQLiteURL reports whether a DATABASE_URL selects SQLite.
func IsSQLiteURL(databaseURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(databaseURL)), SQLiteURLPrefix)
}

// Migrator applies schema migrations.
type Migrator struct {
	m *migrate.Migrate

	// sourceDir is the embedded migration set this database uses, kept so
	// Latest can report the newest version without a database round trip.
	sourceDir string
}

// NewMigrator prepares migrations against the given database URL.
//
// It takes a URL rather than a Store because golang-migrate needs its own
// database/sql handle; sharing the pgx pool is not supported.
func NewMigrator(databaseURL string) (*Migrator, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("migrate: database URL is required")
	}

	sourceDir := migrationsDir(databaseURL)

	source, err := iofs.New(migrationsFS, sourceDir)
	if err != nil {
		return nil, fmt.Errorf("migrate: load embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("migrate: open database: %w", err)
	}
	return &Migrator{m: m, sourceDir: sourceDir}, nil
}

// Up applies all pending migrations. Applying an already-current schema is not
// an error, so this is safe to run on every start.
func (m *Migrator) Up() error {
	if err := m.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// Down reverts the most recent migration.
//
// It steps back one migration rather than tearing everything down, because
// `migrate down` on a database holding real deployment history should not be a
// single command away from dropping all of it.
func (m *Migrator) Down() error {
	// Stepping back from an empty schema is a no-op. golang-migrate's
	// Steps(-1) reports os.ErrNotExist rather than ErrNoChange when no
	// version has ever been applied, so check for the nil version first.
	if _, _, err := m.m.Version(); errors.Is(err, migrate.ErrNilVersion) {
		return nil
	}
	if err := m.m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// Version reports the current schema version and whether the last migration
// left the database dirty (failed partway and needs manual attention).
func (m *Migrator) Version() (version uint, dirty bool, err error) {
	version, dirty, err = m.m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("migrate version: %w", err)
	}
	return version, dirty, nil
}

// Latest reports the newest migration version embedded in this binary for the
// migrator's dialect. Comparing it with Version tells an operator whether
// `soroforge migrate up` still has work to do, without applying anything.
func (m *Migrator) Latest() (uint, error) {
	return latestVersion(m.sourceDir)
}

// migrationsDir selects the embedded migration set for a database URL.
func migrationsDir(databaseURL string) string {
	if IsSQLiteURL(databaseURL) {
		return "migrations/sqlite"
	}
	return "migrations/postgres"
}

// latestVersion scans an embedded migration directory for the highest
// numbered *.up.sql file. golang-migrate names versions by that numeric
// prefix, so this is the version a fully migrated schema reports.
func latestVersion(dir string) (uint, error) {
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return 0, fmt.Errorf("migrate: read embedded migrations: %w", err)
	}
	var latest uint64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		version, err := strconv.ParseUint(prefix, 10, 64)
		if err != nil {
			continue
		}
		latest = max(latest, version)
	}
	if latest == 0 {
		return 0, fmt.Errorf("migrate: no migrations embedded in %s", dir)
	}
	return uint(latest), nil
}

// Close releases the migrator's database handles.
func (m *Migrator) Close() error {
	sourceErr, dbErr := m.m.Close()
	return errors.Join(sourceErr, dbErr)
}

// MigrationsFS exposes the embedded migrations for tests that build a schema
// directly and for the dialect-parity check.
func MigrationsFS() embed.FS { return migrationsFS }
