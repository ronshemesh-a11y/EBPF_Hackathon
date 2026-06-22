package analyzer

// Result cache lifted from P2's scorer/cache.go: a bounded FIFO keyed by a hash
// of executable+argv, so a repeated command reuses its score while the
// per-event fields (pid/ts) are re-stamped for the new occurrence. Safe for
// concurrent use.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// argvKey returns a stable key for an exec+argv pair: sha256 over the executable
// and each argv element, NUL-separated so distinct splits can't collide.
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

type cache struct {
	mu    sync.Mutex
	cap   int
	items map[string]scoreResult
	order []string
}

func newCache(capacity int) *cache {
	if capacity < 1 {
		capacity = 1
	}
	return &cache{cap: capacity, items: make(map[string]scoreResult, capacity)}
}

func (c *cache) get(key string) (scoreResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.items[key]
	return r, ok
}

func (c *cache) put(key string, r scoreResult) {
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
