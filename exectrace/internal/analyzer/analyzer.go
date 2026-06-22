// Package analyzer is P2's LLM scorer, lifted out of its standalone `scorer`
// binary (package main) into an importable library that implements
// types.Scorer. It scores a single exec event with a local Ollama model and
// returns a types.Verdict, so cmd/report and cmd/eval consume it in-process via
// the same seam mockp2 used — a one-line construction swap.
//
// The valuable P2 IP (system prompt, few-shot pairs, robust JSON extraction,
// single-flight result cache) is preserved here; only the types and the method
// signature are adapted to P3's contract (Score(Event) Verdict, no ctx/err).
// Scoring failures surface as a GRAY "error" verdict rather than crashing,
// matching P2's never-silently-drop policy.
package analyzer

import (
	"context"
	"strings"
	"time"

	"exectrace/internal/types"
)

// scoreResult is the model's judgement before banding/stamping (P2's
// ScoreResult). Kept internal — callers only see types.Verdict.
type scoreResult struct {
	RiskScore      float64
	Verdict        string
	Reason         string
	Mitre          []string
	RiskIndicators []string
}

// backend is the seam between the analyzer and a model client. OllamaClient
// (real) and mockBackend (dev fallback) both satisfy it.
type backend interface {
	score(ctx context.Context, e types.Event) (scoreResult, error)
	name() string
}

// Band cutoffs (P2's thresholds): HIGH ≥ 0.75, GRAY ≥ 0.35, else LOW.
const (
	highThreshold = 0.75
	grayThreshold = 0.35
)

func bandFor(score float64) string {
	switch {
	case score >= highThreshold:
		return types.BandHigh
	case score >= grayThreshold:
		return types.BandGray
	default:
		return types.BandLow
	}
}

func verdictForScore(score float64) string {
	switch bandFor(score) {
	case types.BandHigh:
		return "malicious"
	case types.BandGray:
		return "suspicious"
	default:
		return "benign"
	}
}

// Analyzer scores exec events via a model backend, with a single-flight result
// cache so repeated identical commands are scored once. It implements
// types.Scorer.
type Analyzer struct {
	be      backend
	cache   *cache
	timeout time.Duration
}

// Option configures an Analyzer.
type Option func(*Analyzer)

// WithTimeout bounds a single Score call (default 60s).
func WithTimeout(d time.Duration) Option {
	return func(a *Analyzer) { a.timeout = d }
}

// WithCacheSize sets the result cache capacity (default 1024).
func WithCacheSize(n int) Option {
	return func(a *Analyzer) { a.cache = newCache(n) }
}

// New returns an Analyzer backed by a local Ollama model. It satisfies
// types.Scorer, so it drops into cmd/report and cmd/eval in one line:
//
//	var scorer types.Scorer = analyzer.New("llama3.2:1b")
func New(model string, opts ...Option) *Analyzer {
	a := &Analyzer{
		be:      newOllamaClient(model),
		cache:   newCache(1024),
		timeout: 60 * time.Second,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// NewMock returns an Analyzer backed by the keyword heuristic (no model). For
// dev/CI where Ollama isn't running. Not a detection floor — the design is
// LLM-only.
func NewMock(opts ...Option) *Analyzer {
	a := &Analyzer{be: mockBackend{}, cache: newCache(1024), timeout: 5 * time.Second}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Backend names the active model backend (for logs/results).
func (a *Analyzer) Backend() string { return a.be.name() }

// Compile-time proof the analyzer satisfies the P2↔P3 seam.
var _ types.Scorer = (*Analyzer)(nil)

// Score judges one Event and returns a Verdict. Synchronous per the
// types.Scorer contract: it manages its own context/timeout and converts a
// backend error into a GRAY "error" verdict (never a panic, never a drop).
func (a *Analyzer) Score(e types.Event) types.Verdict {
	key := argvKey(e.Executable, e.Argv)
	source := "cache"
	r, ok := a.cache.get(key)
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		defer cancel()
		var err error
		r, err = a.be.score(ctx, e)
		if err != nil {
			return errorVerdict(e, err)
		}
		a.cache.put(key, r)
		source = "llm"
	}
	return verdictFrom(e, r, source)
}

// commandLine renders argv as one string (argv[0] carries the program name);
// falls back to the executable path.
func commandLine(e types.Event) string {
	if len(e.Argv) > 0 {
		return strings.Join(e.Argv, " ")
	}
	return e.Executable
}

// verdictFrom assembles a types.Verdict from an event and a score result. Band
// is derived from the score so it always agrees with it; the first MITRE
// technique doubles as the tactic hint (P3's Verdict carries a single Tactic).
func verdictFrom(e types.Event, r scoreResult, source string) types.Verdict {
	verdict := strings.TrimSpace(r.Verdict)
	if verdict == "" {
		verdict = verdictForScore(r.RiskScore)
	}
	reason := r.Reason
	if len(r.RiskIndicators) > 0 {
		reason = strings.TrimSpace(reason + " [" + strings.Join(r.RiskIndicators, ",") + "]")
	}
	return types.Verdict{
		Pid:     e.Pid,
		Command: commandLine(e),
		Score:   r.RiskScore,
		Band:    bandFor(r.RiskScore),
		Verdict: verdict,
		Reason:  reason,
		Mitre:   r.Mitre,
		Source:  source,
		Ts:      e.Ts,
	}
}

// errorVerdict is returned when the backend fails: a GRAY "error" verdict so the
// failure is visible downstream rather than silently benign.
func errorVerdict(e types.Event, err error) types.Verdict {
	return types.Verdict{
		Pid:     e.Pid,
		Command: commandLine(e),
		Score:   0.5,
		Band:    types.BandGray,
		Verdict: "error",
		Reason:  "scorer error: " + err.Error(),
		Source:  "error",
		Ts:      e.Ts,
	}
}
