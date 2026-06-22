// Package server turns the verdict stream into a live web app: it keeps the
// last N verdicts in memory and pushes each new one to connected browsers over
// a websocket. It reuses types.Verdict as-is — no new contract — so any verdict
// producer (report --json, the scorer binary, …) feeds it.
package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"exectrace/internal/store"
	"exectrace/internal/types"
)

// distFS holds the built React SOC console (web/ → vite build → dist/). Embedded
// so the single `server` binary serves the whole UI; no separate Node server.
//
//go:embed all:dist
var distFS embed.FS

// ringSize is how many recent verdicts a freshly-connected browser receives.
const ringSize = 500

// VerdictStore is the persistence the server needs: write each verdict and read
// back filtered history. *store.Store satisfies it. May be nil (in-memory only,
// e.g. tests) — the server degrades gracefully.
type VerdictStore interface {
	Insert(types.Verdict) error
	Query(store.Filter) ([]types.Verdict, error)
}

// Server holds the recent-verdict ring buffer, the set of live websocket
// clients, and (optionally) durable storage. Safe for concurrent use: Publish
// (one producer goroutine) and the HTTP handlers (one goroutine per request)
// all go through the mutex.
type Server struct {
	mu      sync.Mutex
	ring    []types.Verdict // most-recent-last, capped at ringSize
	clients map[*client]struct{}

	store    VerdictStore // nil = no persistence
	logf     func(string, ...any)
	upgrader websocket.Upgrader
}

// New builds a Server. st may be nil for in-memory-only operation.
func New(st VerdictStore) *Server {
	return &Server{
		clients: make(map[*client]struct{}),
		store:   st,
		logf:    func(string, ...any) {},
		upgrader: websocket.Upgrader{
			// Single-host demo tool: accept any origin so the page served from
			// :8080 (and curl/wscat) can connect without CORS friction.
			CheckOrigin: func(*http.Request) bool { return true },
		},
	}
}

// SetLogf installs a logger for non-fatal errors (e.g. a failed DB insert).
func (s *Server) SetLogf(f func(string, ...any)) {
	if f != nil {
		s.logf = f
	}
}

// Handler returns the HTTP mux: GET / (the embedded React SPA + its assets),
// GET /ws (websocket), and GET /api/verdicts (history).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/api/verdicts", s.handleAPIVerdicts)
	mux.Handle("/", s.spaHandler())
	return mux
}

// spaHandler serves the built SPA from the embedded dist/. Real files (JS, CSS,
// fonts) are served directly; any other path falls back to index.html so
// client-side routing works.
func (s *Server) spaHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// dist not embedded (shouldn't happen in a built binary): serve a hint.
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "UI not built: run `make ui` (npm build) then rebuild the server", http.StatusServiceUnavailable)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	index, _ := fs.ReadFile(sub, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the file if it exists; otherwise hand back index.html (SPA).
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			serveIndex(w, index)
			return
		}
		if f, err := sub.Open(p); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, index)
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(index)
}

// Publish persists a verdict (if a store is set), records it in the ring, and
// pushes it to every connected client. Called by the stdin reader goroutine
// for each decoded verdict.
func (s *Server) Publish(v types.Verdict) {
	if s.store != nil {
		if err := s.store.Insert(v); err != nil {
			s.logf("store insert: %v", err)
		}
	}

	s.mu.Lock()
	s.ring = append(s.ring, v)
	if len(s.ring) > ringSize {
		s.ring = s.ring[len(s.ring)-ringSize:]
	}
	clients := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()

	for _, c := range clients {
		c.send(v)
	}
}

// handleAPIVerdicts serves history from the store as JSON:
// GET /api/verdicts?limit=&band=&since=  (since = RFC3339).
func (s *Server) handleAPIVerdicts(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, []types.Verdict{}) // no persistence: empty history
		return
	}
	q := r.URL.Query()
	f := store.Filter{Band: q.Get("band")}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			f.Limit = n
		}
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Since = t
		}
	}
	rows, err := s.store.Query(f)
	if err != nil {
		s.logf("api query: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []types.Verdict{}
	}
	writeJSON(w, rows)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrader already wrote the error
	}
	c := newClient(conn)

	// Register, then snapshot the ring so the new client gets the backlog. Take
	// the snapshot under the lock with registration so we can't miss a verdict
	// published between snapshot and register.
	s.mu.Lock()
	backlog := make([]types.Verdict, len(s.ring))
	copy(backlog, s.ring)
	s.clients[c] = struct{}{}
	s.mu.Unlock()

	go c.writeLoop()
	for _, v := range backlog {
		c.send(v)
	}

	// Block reading until the client goes away (we don't expect inbound
	// messages; this also drains control frames). On exit, unregister.
	c.readUntilClose()
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()
	c.close()
}

// --- client -------------------------------------------------------------

const (
	writeWait  = 5 * time.Second
	sendBuffer = 256
)

// client is one websocket connection with a buffered outbound queue and a
// single writer goroutine (gorilla forbids concurrent writes).
type client struct {
	conn      *websocket.Conn
	out       chan []byte
	closeOnce sync.Once
}

func newClient(conn *websocket.Conn) *client {
	return &client{conn: conn, out: make(chan []byte, sendBuffer)}
}

// send queues a verdict as JSON. Non-blocking: if the client's buffer is full
// (slow browser), drop rather than stall the whole stream.
func (c *client) send(v types.Verdict) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.out <- b:
	default: // slow consumer — drop this verdict for this client
	}
}

func (c *client) writeLoop() {
	for b := range c.out {
		c.conn.SetWriteDeadline(time.Now().Add(writeWait))
		if err := c.conn.WriteMessage(websocket.TextMessage, b); err != nil {
			c.close()
			return
		}
	}
}

// readUntilClose blocks reading inbound frames (none expected) until the peer
// closes or errors, so the writer can be torn down.
func (c *client) readUntilClose() {
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *client) close() {
	c.closeOnce.Do(func() {
		close(c.out)
		c.conn.Close()
	})
}
