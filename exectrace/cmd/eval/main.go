// Command eval benchmarks whatever scorer is plugged in against labeled ground
// truth, and prints a scorecard. It reads a labeled CSV corpus, scores every
// row, and reports recall / precision / F1 / TP / FP / FN — plus the false
// positives and missed rows, which are the point: they are what you tune
// against.
//
//	eval --file testdata/attack_linux_labeled.csv [--truth gt.txt] [--out results.json]
//
// Labels come from the corpus's own 3rd column by default. --truth points at a
// separate ground-truth file (one malicious command_line per line; blanks and
// '#' comments ignored; matched whitespace-normalized) — a command present
// there is a positive, everything else a negative.
//
// Stream-oriented: no "cap at N", no assumed total. recall/precision come from
// per-row labels only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"exectrace/internal/analyzer"
	"exectrace/internal/eval"
	"exectrace/internal/mockp2"
	"exectrace/internal/source"
	"exectrace/internal/types"
)

// buildScorer selects the scorer backend behind the types.Scorer seam:
// mockp2 (default, offline), llm (P2 analyzer/Ollama), llm-mock (P2 keyword).
func buildScorer(name, model string, gray, high float64) types.Scorer {
	switch name {
	case "llm":
		return analyzer.New(model)
	case "llm-mock":
		return analyzer.NewMock()
	default:
		return mockp2.New(mockp2.Bands{Gray: gray, High: high})
	}
}

func main() {
	file := flag.String("file", "", "labeled CSV corpus to score (process_name,command_line[,label])")
	truth := flag.String("truth", "", "optional ground-truth file (.txt: one malicious command per line)")
	out := flag.String("out", "", "persist the run as JSON to this path")
	scorerName := flag.String("scorer", "mockp2", "scorer + results label: mockp2 | llm (P2 Ollama) | llm-mock")
	model := flag.String("model", "llama3.2:1b", "Ollama model for --scorer=llm")
	grayCut := flag.Float64("gray", 0.3, "score cutoff for GRAY band")
	highCut := flag.Float64("high", 0.7, "score cutoff for HIGH band")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "eval: --file is required")
		os.Exit(2)
	}

	base := time.Unix(0, 0).UTC()
	rows, err := readCSV(*file, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval: %v\n", err)
		os.Exit(1)
	}

	// Label lookup: from the .txt truth file if given, else from the corpus's
	// own label column.
	labelOf := func(i int, cmd string) string { return rows[i].Label }
	if *truth != "" {
		tf, err := os.Open(*truth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eval: truth: %v\n", err)
			os.Exit(1)
		}
		tset, err := eval.LoadTruth(tf)
		tf.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "eval: truth: %v\n", err)
			os.Exit(1)
		}
		labelOf = func(_ int, cmd string) string { return tset.Label(cmd) }
	}

	// Seam with P2: held as the interface. --scorer selects the backend (real
	// P2 is the analyzer/Ollama); default mockp2 keeps the benchmark offline.
	scorer := buildScorer(*scorerName, *model, *grayCut, *highCut)
	var es eval.Scorer

	t0 := time.Now()
	labeled := 0
	for i, row := range rows {
		v := scorer.Score(row.Event)
		label := labelOf(i, v.Command)
		// With the corpus label column, an empty label means "unlabeled — skip".
		// With a truth file, every row gets benign/malicious, so nothing is
		// skipped (which is what we want: benign rows are real negatives).
		if *truth == "" && label == "" {
			continue
		}
		labeled++
		es.Observe(v, label)
	}
	es.Elapsed = time.Since(t0)

	if labeled == 0 {
		fmt.Fprintln(os.Stderr, "eval: no labeled rows found (corpus has no label column and no --truth given)")
		os.Exit(1)
	}

	fmt.Printf("corpus=%s  scorer=%s  labeled_rows=%d\n", *file, *scorerName, labeled)
	fmt.Print(es.Report())

	if *out != "" {
		res := es.Result(*file, *scorerName, time.Now().UTC().Format(time.RFC3339))
		if err := writeJSON(*out, res); err != nil {
			fmt.Fprintf(os.Stderr, "eval: write %s: %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	}
}

func readCSV(path string, base time.Time) ([]source.Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return source.Read(f, base)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
