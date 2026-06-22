// Command compare diffs two persisted benchmark runs (written by `eval --out`)
// and prints recall/precision/F1 deltas plus what moved: newly caught, newly
// missed, and false positives added/removed. This sets up the "with vs without
// LLM" before/after story.
//
//	compare A.json B.json
//
// A is the baseline, B is the new run.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"exectrace/internal/eval"
)

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: compare A.json B.json")
		os.Exit(2)
	}
	a, err := load(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		os.Exit(1)
	}
	b, err := load(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(eval.Compare(a, b).Report())
}

func load(path string) (eval.Result, error) {
	var r eval.Result
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	return r, json.NewDecoder(f).Decode(&r)
}
