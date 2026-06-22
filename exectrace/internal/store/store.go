// Package store persists verdicts to a single SQLite file so the web page can
// show history across restarts, not just the live moment. It uses the pure-Go
// modernc.org/sqlite driver (no cgo) so it builds without a C toolchain, here
// and in Docker later.
//
// The DB row mirrors the unified types.Verdict — mitre and risk_indicators are
// each stored as a JSON-array string in one column.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"exectrace/internal/types"
)

const schema = `
CREATE TABLE IF NOT EXISTS verdicts (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	ts              TEXT NOT NULL,
	executable      TEXT NOT NULL,
	command         TEXT NOT NULL,
	risk_score      REAL NOT NULL,
	band            TEXT NOT NULL,
	verdict         TEXT NOT NULL,
	reason          TEXT NOT NULL,
	mitre           TEXT NOT NULL,  -- JSON array
	risk_indicators TEXT NOT NULL,  -- JSON array
	source          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts   ON verdicts(ts);
CREATE INDEX IF NOT EXISTS idx_verdicts_band ON verdicts(band);
`

// Store is a thin wrapper over a SQLite connection holding verdicts.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite file at path and ensures the
// schema exists.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// modernc sqlite is fine with a small pool; keep it simple and serialized.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// Insert persists one verdict. mitre and risk_indicators are each serialized to
// a JSON array string.
func (s *Store) Insert(v types.Verdict) error {
	mitre, err := json.Marshal(normSlice(v.Mitre))
	if err != nil {
		return err
	}
	indicators, err := json.Marshal(normSlice(v.RiskIndicators))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO verdicts (ts, executable, command, risk_score, band, verdict, reason, mitre, risk_indicators, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.Ts.UTC().Format(time.RFC3339Nano), v.Executable, v.Command, v.RiskScore, v.Band,
		v.Verdict, v.Reason, string(mitre), string(indicators), v.Source,
	)
	if err != nil {
		return fmt.Errorf("insert verdict: %w", err)
	}
	return nil
}

// Filter narrows a history query. Zero-value fields are ignored.
type Filter struct {
	Limit int       // max rows (default 100, capped at 1000)
	Band  string    // exact band match (LOW|GRAY|HIGH); "" = any
	Since time.Time // only verdicts at/after this time; zero = no lower bound
}

// Query returns recent verdicts matching the filter, newest first.
func (s *Store) Query(f Filter) ([]types.Verdict, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	q := `SELECT ts, executable, command, risk_score, band, verdict, reason, mitre, risk_indicators, source FROM verdicts`
	var where []string
	var args []any
	if b := strings.ToUpper(strings.TrimSpace(f.Band)); b != "" {
		where = append(where, "band = ?")
		args = append(args, b)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query verdicts: %w", err)
	}
	defer rows.Close()

	var out []types.Verdict
	for rows.Next() {
		var (
			v        types.Verdict
			tsStr    string
			mitreStr string
			indStr   string
		)
		if err := rows.Scan(&tsStr, &v.Executable, &v.Command, &v.RiskScore, &v.Band,
			&v.Verdict, &v.Reason, &mitreStr, &indStr, &v.Source); err != nil {
			return nil, err
		}
		v.Ts, _ = time.Parse(time.RFC3339Nano, tsStr)
		if mitreStr != "" {
			_ = json.Unmarshal([]byte(mitreStr), &v.Mitre)
		}
		if indStr != "" {
			_ = json.Unmarshal([]byte(indStr), &v.RiskIndicators)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Count returns the total number of stored verdicts (used by tests/health).
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM verdicts`).Scan(&n)
	return n, err
}

// normSlice maps a nil slice to an empty slice so the stored JSON is "[]" not
// "null" — keeps the column shape consistent.
func normSlice(m []string) []string {
	if m == nil {
		return []string{}
	}
	return m
}
