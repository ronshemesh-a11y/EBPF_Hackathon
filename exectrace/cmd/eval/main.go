// Command eval benchmarks the pipeline against labeled ground truth. It reads a
// labeled CSV corpus, scores every row through the P2 scorer, and reports
// recall / precision / TP / FP against the label column.
//
//	eval --file testdata/sample.csv [--truth other.csv] [--threshold GRAY]
//
// By default labels come from the corpus's own 3rd column. --truth points at a
// separate ground-truth CSV (same process_name,command_line,label shape); when
// given, labels are looked up from it by command line, so the scored corpus and
// the labels can live in different files.
//
// Stream-oriented: no "cap at N", no assumed total. The scorer accumulates one
// row at a time and the corpus can be any size.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"exectrace/internal/eval"
	"exectrace/internal/mockp2"
	"exectrace/internal/source"
)

func main() {
	file := flag.String("file", "", "labeled CSV corpus to score (process_name,command_line[,label])")
	truth := flag.String("truth", "", "optional separate ground-truth CSV; labels looked up by command line")
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

	// Build the label lookup: from --truth if given, else from the corpus rows.
	labelOf := func(i int, cmd string) string { return rows[i].Label }
	if *truth != "" {
		truthRows, err := readCSV(*truth, base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eval: truth: %v\n", err)
			os.Exit(1)
		}
		byCmd := make(map[string]string, len(truthRows))
		for _, tr := range truthRows {
			byCmd[source.CommandLine(tr.Event)] = tr.Label
		}
		labelOf = func(_ int, cmd string) string { return byCmd[cmd] }
	}

	scorer := mockp2.New(mockp2.Bands{Gray: *grayCut, High: *highCut})
	var es eval.Scorer
	labeled := 0
	for i, row := range rows {
		v := scorer.Score(row.Event)
		label := labelOf(i, v.Command)
		if label == "" {
			continue // no ground truth for this row; skip it
		}
		labeled++
		es.Observe(v, label)
	}

	if labeled == 0 {
		fmt.Fprintln(os.Stderr, "eval: no labeled rows found (corpus has no label column and no --truth given)")
		os.Exit(1)
	}

	fmt.Printf("corpus=%s  labeled_rows=%d\n", *file, labeled)
	fmt.Print(es.Report())
}

func readCSV(path string, base time.Time) ([]source.Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return source.Read(f, base)
}
