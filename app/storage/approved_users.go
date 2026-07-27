package storage

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "modernc.org/sqlite" // sqlite driver loaded here

	"github.com/umputun/tg-spam/app/storage/engine"
	"github.com/umputun/tg-spam/lib/approved"
)

// ApprovedUsers is a storage for approved users
type ApprovedUsers struct {
	*engine.SQL
	engine.RWLocker
}

// approvedUsersInfo is a struct to store approved user info in the database
type approvedUsersInfo struct {
	UserID    string    `db:"uid"`
	GroupID   string    `db:"gid"`
	UserName  string    `db:"name"`
	ChatID    int64     `db:"chat_id"`
	Timestamp time.Time `db:"timestamp"`
}

// all approved users queries
const (
	CmdCreateApprovedUsersTable engine.DBCmd = iota + 100
	CmdCreateApprovedUsersIndexes
	CmdAddApprovedUser
	CmdAddUIDColumn
	CmdAddGIDColumn
	CmdAddApprovedChatID
)

// queries holds all approved users queries
var approvedUsersQueries = engine.NewQueryMap().
	Add(CmdCreateApprovedUsersTable, engine.Query{
		Sqlite: `CREATE TABLE IF NOT EXISTS approved_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            gid TEXT DEFAULT '',
            name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			chat_id INTEGER NOT NULL DEFAULT 0,
			UNIQUE(gid, chat_id, uid)
        )`,
		Postgres: `CREATE TABLE IF NOT EXISTS approved_users (
            id SERIAL PRIMARY KEY,
            uid TEXT,
            gid TEXT DEFAULT '',
            name TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			chat_id BIGINT NOT NULL DEFAULT 0,
			UNIQUE(gid, chat_id, uid)
        )`,
	}).
	AddSame(CmdCreateApprovedUsersIndexes, `
        CREATE INDEX IF NOT EXISTS idx_approved_users_uid ON approved_users(uid);
        CREATE INDEX IF NOT EXISTS idx_approved_users_gid ON approved_users(gid);
        CREATE INDEX IF NOT EXISTS idx_approved_users_name ON approved_users(name);
		CREATE INDEX IF NOT EXISTS idx_approved_users_timestamp ON approved_users(timestamp);
		CREATE INDEX IF NOT EXISTS idx_approved_users_gid_chat ON approved_users(gid, chat_id)
    `).
	Add(CmdAddApprovedUser, engine.Query{
		Sqlite: "INSERT OR REPLACE INTO approved_users (uid, gid, name, timestamp, chat_id) VALUES (?, ?, ?, ?, ?)",
		Postgres: "INSERT INTO approved_users (uid, gid, name, timestamp, chat_id) VALUES ($1, $2, $3, $4, $5) " +
			"ON CONFLICT (gid, chat_id, uid) DO UPDATE SET name=EXCLUDED.name, timestamp=EXCLUDED.timestamp",
	}).
	Add(CmdAddUIDColumn, engine.Query{
		Sqlite:   "ALTER TABLE approved_users ADD COLUMN uid TEXT",
		Postgres: "ALTER TABLE approved_users ADD COLUMN IF NOT EXISTS uid TEXT",
	}).
	Add(CmdAddGIDColumn, engine.Query{
		Sqlite:   "ALTER TABLE approved_users ADD COLUMN gid TEXT DEFAULT ''",
		Postgres: "ALTER TABLE approved_users ADD COLUMN IF NOT EXISTS gid TEXT DEFAULT ''",
	}).
	Add(CmdAddApprovedChatID, engine.Query{
		Sqlite:   "ALTER TABLE approved_users ADD COLUMN chat_id INTEGER NOT NULL DEFAULT 0",
		Postgres: "ALTER TABLE approved_users ADD COLUMN IF NOT EXISTS chat_id BIGINT NOT NULL DEFAULT 0",
	})

// NewApprovedUsers creates a new ApprovedUsers storage
func NewApprovedUsers(ctx context.Context, db *engine.SQL) (*ApprovedUsers, error) {
	if db == nil {
		return nil, fmt.Errorf("db connection is nil")
	}
	res := &ApprovedUsers{SQL: db, RWLocker: db.MakeLock()}
	cfg := engine.TableConfig{
		Name:          "approved_users",
		CreateTable:   CmdCreateApprovedUsersTable,
		CreateIndexes: CmdCreateApprovedUsersIndexes,
		MigrateFunc:   res.migrate,
		QueriesMap:    approvedUsersQueries,
	}
	if err := engine.InitTable(ctx, db, cfg); err != nil {
		return nil, fmt.Errorf("failed to init approved users storage: %w", err)
	}
	return res, nil
}

// Read returns a list of all approved users
func (au *ApprovedUsers) Read(ctx context.Context) ([]approved.UserInfo, error) {
	au.RLock()
	defer au.RUnlock()

	query := au.Adopt("SELECT uid, gid, name, timestamp, chat_id FROM approved_users WHERE gid = ? ORDER BY uid, chat_id ASC")
	users := []approvedUsersInfo{}
	if err := au.SelectContext(ctx, &users, query, au.GID()); err != nil {
		return nil, fmt.Errorf("failed to get approved users: %w", err)
	}

	res := make([]approved.UserInfo, len(users))
	for i, u := range users {
		res[i] = approved.UserInfo{
			UserID:    u.UserID,
			UserName:  u.UserName,
			ChatID:    u.ChatID,
			Timestamp: u.Timestamp,
		}
	}
	log.Printf("[DEBUG] read %d approved users", len(res))
	return res, nil
}

// Write adds a user to the approved list
func (au *ApprovedUsers) Write(ctx context.Context, user approved.UserInfo) error {
	if user.UserID == "" {
		return fmt.Errorf("user id can't be empty")
	}

	au.Lock()
	defer au.Unlock()

	if user.Timestamp.IsZero() {
		user.Timestamp = time.Now()
	}

	query, err := approvedUsersQueries.Pick(au.Type(), CmdAddApprovedUser)
	if err != nil {
		return fmt.Errorf("failed to get write query: %w", err)
	}

	if _, err := au.ExecContext(ctx, query, user.UserID, au.GID(), user.UserName, user.Timestamp, user.ChatID); err != nil {
		return fmt.Errorf("failed to insert user %+v: %w", user, err)
	}

	log.Printf("[INFO] user %q (%s) added to approved users", user.UserName, user.UserID)
	return nil
}

// Delete removes a user from the approved list
func (au *ApprovedUsers) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("user id can't be empty")
	}

	au.Lock()
	defer au.Unlock()

	// check if user exists first
	var user approvedUsersInfo
	query := au.Adopt("SELECT uid, gid, name, timestamp, chat_id FROM approved_users WHERE uid = ? AND gid = ? LIMIT 1")
	if err := au.GetContext(ctx, &user, query, id, au.GID()); err != nil {
		return fmt.Errorf("failed to get approved user for id %s: %w", id, err)
	}

	// delete user  "DELETE FROM approved_users WHERE uid = ? AND gid = ?"
	query = au.Adopt("DELETE FROM approved_users WHERE uid = ? AND gid = ?")
	if _, err := au.ExecContext(ctx, query, id, au.GID()); err != nil {
		return fmt.Errorf("failed to delete id %s: %w", id, err)
	}

	log.Printf("[INFO] user %q (%s) deleted from approved users", user.UserName, id)
	return nil
}

// migrateTableTx handles migration within a transaction
func (au *ApprovedUsers) migrate(ctx context.Context, tx *sqlx.Tx, gid string) error {
	// try to select with new structure, if works - already migrated
	var count int
	err := tx.GetContext(ctx, &count, "SELECT COUNT(*) FROM approved_users WHERE uid='' AND gid=''")
	legacyColumnsReady := err == nil

	// add legacy columns when upgrading the original id-only table
	if !legacyColumnsReady {
		addUIDQuery, pickErr := approvedUsersQueries.Pick(au.Type(), CmdAddUIDColumn)
		if pickErr != nil {
			return fmt.Errorf("failed to get add UID query: %w", pickErr)
		}

		_, err = tx.ExecContext(ctx, addUIDQuery)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("failed to add uid column: %w", err)
		}

		addGIDQuery, pickErr := approvedUsersQueries.Pick(au.Type(), CmdAddGIDColumn)
		if pickErr != nil {
			return fmt.Errorf("failed to get add GID query: %w", pickErr)
		}

		_, err = tx.ExecContext(ctx, addGIDQuery)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("failed to add gid column: %w", err)
		}

		migrateQuery := au.Adopt("UPDATE approved_users SET uid = id, gid = ? WHERE uid IS NULL OR uid = ''")
		if _, err = tx.ExecContext(ctx, migrateQuery, gid); err != nil {
			return fmt.Errorf("failed to migrate data: %w", err)
		}

		log.Printf("[DEBUG] approved_users table migrated")
	}

	var hasChatID int
	switch au.Type() {
	case engine.Sqlite:
		err = tx.GetContext(ctx, &hasChatID, "SELECT COUNT(*) FROM pragma_table_info('approved_users') WHERE name = 'chat_id'")
	case engine.Postgres:
		err = tx.GetContext(ctx, &hasChatID, `SELECT COUNT(*) FROM information_schema.columns
			WHERE table_name='approved_users' AND column_name='chat_id' AND table_schema=current_schema()`)
	}
	if err != nil {
		return fmt.Errorf("failed to inspect approved user chat scope: %w", err)
	}
	if hasChatID == 0 {
		query, pickErr := approvedUsersQueries.Pick(au.Type(), CmdAddApprovedChatID)
		if pickErr != nil {
			return fmt.Errorf("failed to get approved chat migration: %w", pickErr)
		}
		if _, err = tx.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to add approved chat scope: %w", err)
		}
	}

	ready, err := au.hasScopedUnique(ctx, tx)
	if err != nil || ready {
		return err
	}
	if au.Type() == engine.Sqlite {
		return au.rebuildApprovedUsersSqlite(ctx, tx)
	}
	return au.migrateApprovedUsersPostgres(ctx, tx)
}

func (au *ApprovedUsers) rebuildApprovedUsersSqlite(ctx context.Context, tx *sqlx.Tx) error {
	stmts := []string{
		`CREATE TABLE approved_users_new (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT, gid TEXT DEFAULT '',
			name TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, chat_id INTEGER NOT NULL DEFAULT 0,
			UNIQUE(gid, chat_id, uid))`,
		`INSERT OR REPLACE INTO approved_users_new (uid, gid, name, timestamp, chat_id)
			SELECT uid, COALESCE(gid, ''), name, timestamp, COALESCE(chat_id, 0) FROM approved_users
			ORDER BY timestamp ASC, rowid ASC`,
		"DROP TABLE approved_users",
		"ALTER TABLE approved_users_new RENAME TO approved_users",
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to rebuild approved users: %w", err)
		}
	}
	return nil
}

func (au *ApprovedUsers) migrateApprovedUsersPostgres(ctx context.Context, tx *sqlx.Tx) error {
	var constraints []string
	query := `SELECT tc.constraint_name FROM information_schema.table_constraints tc
		WHERE tc.table_name='approved_users' AND tc.constraint_type='UNIQUE' AND tc.table_schema=current_schema()`
	if err := tx.SelectContext(ctx, &constraints, query); err != nil {
		return fmt.Errorf("failed to list approved user constraints: %w", err)
	}
	for _, constraint := range constraints {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE approved_users DROP CONSTRAINT "+pq.QuoteIdentifier(constraint)); err != nil {
			return fmt.Errorf("failed to drop approved user constraint: %w", err)
		}
	}
	stmts := []string{
		`UPDATE approved_users SET gid = '' WHERE gid IS NULL`,
		`UPDATE approved_users SET chat_id = 0 WHERE chat_id IS NULL`,
		`WITH ranked AS (
			SELECT ctid, ROW_NUMBER() OVER (
				PARTITION BY gid, chat_id, uid ORDER BY timestamp DESC NULLS LAST, ctid DESC
			) AS pos FROM approved_users WHERE uid IS NOT NULL
		) DELETE FROM approved_users a USING ranked r WHERE a.ctid = r.ctid AND r.pos > 1`,
		`ALTER TABLE approved_users ALTER COLUMN chat_id SET DEFAULT 0`,
		`ALTER TABLE approved_users ALTER COLUMN chat_id SET NOT NULL`,
		`ALTER TABLE approved_users ADD CONSTRAINT approved_users_gid_chat_uid_key
		UNIQUE (gid, chat_id, uid)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to migrate approved user scopes: %w", err)
		}
	}
	return nil
}

func (au *ApprovedUsers) hasScopedUnique(ctx context.Context, tx *sqlx.Tx) (bool, error) {
	var count int
	var query string
	switch au.Type() {
	case engine.Sqlite:
		query = `SELECT COUNT(*) FROM pragma_index_list('approved_users') il WHERE il."unique"=1 AND
			(SELECT group_concat(name, ',') FROM pragma_index_info(il.name))='gid,chat_id,uid'`
	case engine.Postgres:
		query = `SELECT COUNT(*) FROM (SELECT tc.constraint_name,
			string_agg(kcu.column_name, ',' ORDER BY kcu.ordinal_position) cols
			FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu
			ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema
			WHERE tc.table_name='approved_users' AND tc.constraint_type='UNIQUE' AND tc.table_schema=current_schema()
			GROUP BY tc.constraint_name) q WHERE cols='gid,chat_id,uid'`
	default:
		return false, fmt.Errorf("unsupported database type %q", au.Type())
	}
	if err := tx.GetContext(ctx, &count, query); err != nil {
		return false, fmt.Errorf("failed to inspect approved user unique key: %w", err)
	}
	return count > 0, nil
}
