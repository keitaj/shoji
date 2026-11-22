package verifier

import (
	"context"
	"database/sql"
	"errors"

	_ "modernc.org/sqlite"
)

// Store keeps the only state the verifier has. None of it identifies a person:
// outstanding challenges, and per-application nullifiers with a ban flag.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS challenges (
	nonce         BLOB PRIMARY KEY,
	app           TEXT NOT NULL,
	date_int      INTEGER NOT NULL,
	age_threshold INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nullifiers (
	app       TEXT NOT NULL,
	nullifier BLOB NOT NULL,
	banned    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (app, nullifier)
);`

// OpenStore opens (and initialises) a SQLite database. Use ":memory:" in tests.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// A single connection keeps every statement serialised, which is what makes
	// nonce consumption atomic (and keeps ":memory:" databases coherent).
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Challenge is an outstanding nonce together with the public inputs the verifier
// fixed when it issued the nonce.
type Challenge struct {
	Nonce        []byte
	App          string
	CurrentDate  uint32
	AgeThreshold uint8
	ExpiresAt    int64 // unix seconds
}

// PutChallenge stores a new challenge and drops expired ones.
func (s *Store) PutChallenge(ctx context.Context, c Challenge, now int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at < ?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (nonce, app, date_int, age_threshold, expires_at) VALUES (?, ?, ?, ?, ?)`,
		c.Nonce, c.App, c.CurrentDate, c.AgeThreshold, c.ExpiresAt)
	return err
}

// ErrNoChallenge means the nonce is unknown, already used, or expired.
var ErrNoChallenge = errors.New("unknown, used or expired nonce")

// ConsumeChallenge atomically removes the challenge for nonce and returns it.
// A nonce can therefore be consumed at most once, whatever happens afterwards.
func (s *Store) ConsumeChallenge(ctx context.Context, nonce []byte, now int64) (Challenge, error) {
	c := Challenge{Nonce: nonce}
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM challenges WHERE nonce = ? RETURNING app, date_int, age_threshold, expires_at`, nonce).
		Scan(&c.App, &c.CurrentDate, &c.AgeThreshold, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, ErrNoChallenge
	}
	if err != nil {
		return Challenge{}, err
	}
	if c.ExpiresAt < now {
		return Challenge{}, ErrNoChallenge
	}
	return c, nil
}

// RecordNullifier inserts the nullifier for app if it is new. It reports whether
// it was new and whether it is banned.
func (s *Store) RecordNullifier(ctx context.Context, app string, nullifier []byte) (isNew, banned bool, err error) {
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO nullifiers (app, nullifier) VALUES (?, ?)`, app, nullifier)
	if err != nil {
		return false, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, false, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT banned FROM nullifiers WHERE app = ? AND nullifier = ?`, app, nullifier).Scan(&banned)
	return n == 1, banned, err
}

// SetBanned sets the ban flag of a nullifier, creating the row if necessary.
func (s *Store) SetBanned(ctx context.Context, app string, nullifier []byte, banned bool) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nullifiers (app, nullifier, banned) VALUES (?, ?, ?)
		 ON CONFLICT (app, nullifier) DO UPDATE SET banned = excluded.banned`, app, nullifier, banned)
	return err
}
