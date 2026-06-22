package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

// job is one exec event queued for scoring, tagged with its input order so the
// writer can emit verdicts in the same order they arrived.
type job struct {
	seq int
	ev  ExecEvent
}

// seqVerdict carries a finished verdict back to the ordered writer.
type seqVerdict struct {
	seq     int
	verdict Verdict
}

// pool runs the scorer concurrently with single-flight dedup: identical commands
// (same argvKey) are scored once; concurrent or later duplicates reuse the
// cached result. This keeps only DISTINCT commands hitting the model.
type pool struct {
	scorer   Scorer
	cache    *Cache
	mu       sync.Mutex
	inflight map[string]chan struct{}
	scored   int64 // distinct commands sent to the scorer
	hits     int64 // duplicates served from cache
}

// resolve returns the score for an event and the source that produced it.
func (p *pool) resolve(ctx context.Context, ev ExecEvent) (ScoreResult, string) {
	key := argvKey(ev.Executable, ev.Argv)
	for {
		p.mu.Lock()
		if r, ok := p.cache.Get(key); ok {
			p.mu.Unlock()
			atomic.AddInt64(&p.hits, 1)
			return r, "cache"
		}
		if ch, busy := p.inflight[key]; busy {
			// Another worker is scoring this exact command — wait, then retry
			// the loop (it will hit the now-populated cache).
			p.mu.Unlock()
			<-ch
			continue
		}
		// Claim the key so concurrent duplicates wait on us.
		ch := make(chan struct{})
		p.inflight[key] = ch
		p.mu.Unlock()

		r, err := p.scorer.Score(ctx, ev)
		source := "llm"
		if err != nil {
			r = errorResult(err)
			source = "error"
		}

		p.mu.Lock()
		if source == "llm" {
			p.cache.Put(key, r) // only successful scores are cached
		}
		delete(p.inflight, key)
		p.mu.Unlock()
		close(ch) // wake any waiters

		atomic.AddInt64(&p.scored, 1)
		return r, source
	}
}

func main() {
	mock := flag.Bool("mock", false, "use the keyword heuristic instead of a model")
	model := flag.String("model", "phi3", "Ollama model name (ignored with --mock)")
	workers := flag.Int("workers", 4, "number of concurrent scoring workers")
	cacheSize := flag.Int("cache-size", 4096, "max distinct commands to cache")
	flag.Parse()

	var scorer Scorer
	if *mock {
		scorer = MockScorer{}
	} else {
		scorer = NewOllamaClient(*model)
	}
	fmt.Fprintf(os.Stderr, "scorer: backend=%s workers=%d cache=%d\n", scorer.Name(), *workers, *cacheSize)

	// Cancel in-flight model calls cleanly on Ctrl-C / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := &pool{
		scorer:   scorer,
		cache:    NewCache(*cacheSize),
		inflight: make(map[string]chan struct{}),
	}

	jobs := make(chan job, 1024)
	results := make(chan seqVerdict, 1024)

	// Worker pool: each worker scores jobs and forwards tagged verdicts.
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r, src := p.resolve(ctx, j.ev)
				results <- seqVerdict{seq: j.seq, verdict: newVerdict(j.ev, r, src)}
			}
		}()
	}

	// Ordered writer: buffer out-of-order results and flush by input order.
	done := make(chan struct{})
	go func() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false) // commands carry >, &, < — keep them readable
		pending := make(map[int]Verdict)
		next := 0
		for sv := range results {
			pending[sv.seq] = sv.verdict
			for {
				v, ok := pending[next]
				if !ok {
					break
				}
				_ = enc.Encode(v) // Encode appends a newline → JSONL
				delete(pending, next)
				next++
			}
		}
		close(done)
	}()

	// Read loop: decode the envelope, route execs to the pool, skip the rest.
	var read, nonExec int64
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // argv lines can be long
	seq := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		read++

		var env Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			fmt.Fprintf(os.Stderr, "skip malformed line: %v\n", err)
			continue
		}
		if !IsExec(env.EventType) {
			nonExec++
			continue
		}

		var ev ExecEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "skip malformed exec line: %v\n", err)
			continue
		}

		jobs <- job{seq: seq, ev: ev}
		seq++

		if ctx.Err() != nil {
			break // shutting down
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stdin read error: %v\n", err)
	}

	close(jobs)
	wg.Wait()
	close(results)
	<-done

	fmt.Fprintf(os.Stderr, "read=%d exec_scored=%d cache_hits=%d non_exec_skipped=%d\n",
		read, atomic.LoadInt64(&p.scored), atomic.LoadInt64(&p.hits), nonExec)
}
