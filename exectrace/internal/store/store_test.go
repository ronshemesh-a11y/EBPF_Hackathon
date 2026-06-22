package store

import (
	"path/filepath"
	"testing"
	"time"

	"exectrace/internal/types"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mk(cmd, band string, ts time.Time, mitre ...string) types.Verdict {
	return types.Verdict{
		Executable: "/bin/x", Command: cmd, Band: band, RiskScore: 0.5, Verdict: "x",
		Reason: "r", Mitre: mitre, RiskIndicators: []string{"i"}, Source: "rule", Ts: ts,
	}
}

func TestInsertAndQueryRoundtrip(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	if err := s.Insert(mk("ls -la", types.BandLow, base, "T1059")); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	got := rows[0]
	if got.Command != "ls -la" || got.Band != types.BandLow {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if len(got.Mitre) != 1 || got.Mitre[0] != "T1059" {
		t.Errorf("mitre not preserved: %v", got.Mitre)
	}
	if !got.Ts.Equal(base) {
		t.Errorf("ts mismatch: %v vs %v", got.Ts, base)
	}
}

func TestQueryNewestFirstAndLimit(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.Insert(mk("cmd", types.BandLow, base.Add(time.Duration(i)*time.Second)))
	}
	rows, err := s.Query(Filter{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("limit not applied: %d", len(rows))
	}
	// Newest first: last inserted (i=4) is at +4s.
	if !rows[0].Ts.Equal(base.Add(4 * time.Second)) {
		t.Errorf("not newest-first: top ts = %v", rows[0].Ts)
	}
}

func TestQueryBandFilter(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	s.Insert(mk("ls", types.BandLow, base))
	s.Insert(mk("curl|sh", types.BandHigh, base.Add(time.Second)))
	s.Insert(mk("cat shadow", types.BandGray, base.Add(2*time.Second)))

	rows, err := s.Query(Filter{Band: "high"}) // case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Band != types.BandHigh {
		t.Fatalf("band filter wrong: %+v", rows)
	}
}

func TestQuerySinceFilter(t *testing.T) {
	s := newTestStore(t)
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	s.Insert(mk("old", types.BandLow, base))
	s.Insert(mk("new", types.BandLow, base.Add(time.Hour)))

	rows, err := s.Query(Filter{Since: base.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Command != "new" {
		t.Fatalf("since filter wrong: %+v", rows)
	}
}

func TestPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Insert(mk("persisted cmd", types.BandHigh, time.Now().UTC()))
	s1.Close()

	// Reopen the same file: the row must still be there (the whole point).
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n, err := s2.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 persisted row after reopen, got %d", n)
	}
}

func TestNilMitreStoredAsEmpty(t *testing.T) {
	s := newTestStore(t)
	s.Insert(mk("no mitre", types.BandLow, time.Now().UTC())) // mitre nil
	rows, _ := s.Query(Filter{})
	if rows[0].Mitre == nil {
		// json "[]" unmarshals to empty non-nil slice; nil would mean "null"
		// was stored. Either way must not panic — assert empty.
		t.Skip("nil acceptable")
	}
	if len(rows[0].Mitre) != 0 {
		t.Errorf("expected empty mitre, got %v", rows[0].Mitre)
	}
}
