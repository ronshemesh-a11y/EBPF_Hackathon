package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// argvKey returns a stable key for an exec+argv pair: sha256 over the executable
// and each argv element, NUL-separated so distinct splits can never collide
// (e.g. ["a b"] vs ["a","b"]).
func argvKey(executable string, argv []string) string {
	h := sha256.New()
	h.Write([]byte(executable))
	h.Write([]byte{0})
	for _, a := range argv {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Cache is a bounded FIFO of scoring results keyed by argvKey. The model output
// (not the full Verdict) is cached, so a repeated command reuses the score while
// the per-event fields (pid, ts, comm) are re-stamped for the new occurrence.
// Safe for concurrent use by the worker pool.
type Cache struct {
	mu    sync.Mutex
	cap   int
	items map[string]ScoreResult
	order []string
}

// NewCache returns a cache holding at most capacity distinct commands.
func NewCache(capacity int) *Cache {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache{cap: capacity, items: make(map[string]ScoreResult, capacity)}
}

// Get returns a cached result, if present.
func (c *Cache) Get(key string) (ScoreResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.items[key]
	return r, ok
}

// Put stores a result, evicting the oldest entry when at capacity.
func (c *Cache) Put(key string, r ScoreResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; exists {
		c.items[key] = r
		return
	}
	if len(c.order) >= c.cap {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
	c.items[key] = r
	c.order = append(c.order, key)
}
