package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/umputun/tg-spam/app/storage/engine"
)

// Warnings is a storage for admin /warn events used to drive auto-ban decisions.
// methods are safe for concurrent use: Add takes a write lock and CountWithin takes a read lock.
type Warnings struct {
	*engine.SQL
	engine.RWLocker
}

// Warning represents a single admin warning issued to a user
type Warning struct {
	ID        int64     `db:"id"`
	GID       string    `db:"gid"`
	UserID    int64     `db:"user_id"`
	UserName  string    `db:"user_name"`
	ChatID    int64     `db:"chat_id"`
	CreatedAt time.Time `db:"created_at"`
}

// WarningsRetention is the storage cap for warning rows; not the user-configured window.
// older rows are pruned opportunistically on Add to bound storage growth.
// the configured warn window must not exceed this value, otherwise CountWithin would
// silently undercount because relevant rows have already been pruned.
const WarningsRetention = 365 * 24 * time.Hour

// warnings-related command constants
const (
	CmdCreateWarningsTable engine.DBCmd = iota + 600
	CmdCreateWarningsIndexes
	CmdAddWarning
	CmdCountWarningsWithin
	CmdCleanupWarnings
	CmdAddWarningChatID
)

// warningsQueries holds all warnings-related queries
var warningsQueries = engine.NewQueryMap().
	Add(CmdCreateWarningsTable, engine.Query{
		Sqlite: `CREATE TABLE IF NOT EXISTS warnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gid TEXT NOT NULL DEFAULT '',
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL DEFAULT '',
			chat_id INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )`,
		Postgres: `CREATE TABLE IF NOT EXISTS warnings (
            id SERIAL PRIMARY KEY,
            gid TEXT NOT NULL DEFAULT '',
            user_id BIGINT NOT NULL,
            user_name TEXT NOT NULL DEFAULT '',
			chat_id BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )`,
	}).
	AddSame(CmdCreateWarningsIndexes,
		`CREATE INDEX IF NOT EXISTS idx_warnings_gid_user_created ON warnings(gid, user_id, created_at);
		 CREATE INDEX IF NOT EXISTS idx_warnings_gid_chat_user_created ON warnings(gid, chat_id, user_id, created_at)`).
	Add(CmdAddWarning, engine.Query{
		Sqlite: "INSERT INTO warnings (gid, user_id, user_name, chat_id, created_at) " +
			"VALUES (:gid, :user_id, :user_name, :chat_id, :created_at)",
		Postgres: "INSERT INTO warnings (gid, user_id, user_name, chat_id, created_at) " +
			"VALUES (:gid, :user_id, :user_name, :chat_id, :created_at)",
	}).
	AddSame(CmdCountWarningsWithin,
		"SELECT COUNT(*) FROM warnings WHERE gid = ? AND chat_id = ? AND user_id = ? AND created_at > ?").
	AddSame(CmdCleanupWarnings, "DELETE FROM warnings WHERE gid = ? AND created_at < ?").
	Add(CmdAddWarningChatID, engine.Query{
		Sqlite:   "ALTER TABLE warnings ADD COLUMN chat_id INTEGER NOT NULL DEFAULT 0",
		Postgres: "ALTER TABLE warnings ADD COLUMN IF NOT EXISTS chat_id BIGINT NOT NULL DEFAULT 0",
	})

// NewWarnings creates a new Warnings storage and initializes the underlying table
func NewWarnings(ctx context.Context, db *engine.SQL) (*Warnings, error) {
	if db == nil {
		return nil, fmt.Errorf("db connection is nil")
	}
	res := &Warnings{SQL: db, RWLocker: db.MakeLock()}
	cfg := engine.TableConfig{
		Name:          "warnings",
		CreateTable:   CmdCreateWarningsTable,
		CreateIndexes: CmdCreateWarningsIndexes,
		MigrateFunc:   res.migrate,
		QueriesMap:    warningsQueries,
	}
	if err := engine.InitTable(ctx, db, cfg); err != nil {
		return nil, fmt.Errorf("failed to init warnings storage: %w", err)
	}
	return res, nil
}

// migrate adds the chat scope to legacy warning rows.
func (w *Warnings) migrate(ctx context.Context, tx *sqlx.Tx, _ string) error {
	var count int
	var err error
	if w.Type() == engine.Sqlite {
		err = tx.GetContext(ctx, &count, "SELECT COUNT(*) FROM pragma_table_info('warnings') WHERE name='chat_id'")
	} else {
		err = tx.GetContext(ctx, &count, `SELECT COUNT(*) FROM information_schema.columns
			WHERE table_name='warnings' AND column_name='chat_id' AND table_schema=current_schema()`)
	}
	if err != nil || count > 0 {
		if err != nil {
			return fmt.Errorf("failed to inspect warning chat scope: %w", err)
		}
		return nil
	}
	query, err := warningsQueries.Pick(w.Type(), CmdAddWarningChatID)
	if err != nil {
		return fmt.Errorf("failed to get warning chat migration query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to add warning chat scope: %w", err)
	}
	return nil
}

// Add records a single warning for the given user and prunes rows older than the storage retention
// (1 year, independent of the configured warn window). gid and created_at are populated internally
// to match the Reports.Add convention. pruning errors are logged but do not fail the call.
func (w *Warnings) Add(ctx context.Context, userID int64, userName string) error {
	return w.AddInChat(ctx, 0, userID, userName)
}

// AddInChat records a warning for a user in a protected chat.
func (w *Warnings) AddInChat(ctx context.Context, chatID, userID int64, userName string) error {
	w.Lock()
	defer w.Unlock()

	rec := Warning{
		GID:       w.GID(),
		UserID:    userID,
		UserName:  userName,
		ChatID:    chatID,
		CreatedAt: time.Now(),
	}
	query, err := warningsQueries.Pick(w.Type(), CmdAddWarning)
	if err != nil {
		return fmt.Errorf("failed to get insert query: %w", err)
	}
	if _, err := w.NamedExecContext(ctx, query, rec); err != nil {
		return fmt.Errorf("failed to insert warning: %w", err)
	}
	log.Printf("[INFO] warning added: user:%s (%d)", rec.UserName, rec.UserID)

	if err := w.cleanupOld(ctx); err != nil {
		log.Printf("[WARN] failed to cleanup old warnings: %v", err)
	}
	return nil
}

// CountWithin returns the number of warning rows for the given user newer than now-window.
// window must be positive; non-positive values yield meaningless results (callers must pre-validate).
func (w *Warnings) CountWithin(ctx context.Context, userID int64, window time.Duration) (int, error) {
	return w.CountWithinChat(ctx, 0, userID, window)
}

// CountWithinChat returns the warning count for a user in a protected chat.
func (w *Warnings) CountWithinChat(ctx context.Context, chatID, userID int64, window time.Duration) (int, error) {
	w.RLock()
	defer w.RUnlock()

	query, err := warningsQueries.Pick(w.Type(), CmdCountWarningsWithin)
	if err != nil {
		return 0, fmt.Errorf("failed to get query: %w", err)
	}
	query = w.Adopt(query)

	cutoff := time.Now().Add(-window)
	var count int
	if err := w.GetContext(ctx, &count, query, w.GID(), chatID, userID, cutoff); err != nil {
		return 0, fmt.Errorf("failed to count warnings: %w", err)
	}
	return count, nil
}

// cleanupOld deletes warning rows older than WarningsRetention. called from Add (already locked).
func (w *Warnings) cleanupOld(ctx context.Context) error {
	query, err := warningsQueries.Pick(w.Type(), CmdCleanupWarnings)
	if err != nil {
		return fmt.Errorf("failed to get cleanup query: %w", err)
	}
	query = w.Adopt(query)

	cutoff := time.Now().Add(-WarningsRetention)
	result, err := w.ExecContext(ctx, query, w.GID(), cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old warnings: %w", err)
	}
	if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected > 0 {
		log.Printf("[DEBUG] cleaned up %d old warnings (retention: %s)", rowsAffected, WarningsRetention)
	}
	return nil
}
