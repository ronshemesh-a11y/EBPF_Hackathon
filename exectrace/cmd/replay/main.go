// Command replay reads a labeled CSV corpus and emits one NDJSON-encoded
// types.Event per line on stdout, at a configurable rate. It is the bridge that
// lets the whole pipeline run on the corpus instead of live eBPF.
//
// The output stream is plain types.Event JSON — byte-for-byte what a live eBPF
// source would emit — so the reporter/eval cannot tell replay from a kernel
// feed. Swapping replay for the real tracer changes nothing downstream.
//
//	replay --file testdata/sample.csv [--rate 0] > events.ndjson
//
// --rate is events per second (0 = as fast as possible).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"exectrace/internal/source"
)

func main() {
	file := flag.String("file", "", "CSV corpus (process_name,command_line[,label]); '-' for stdin")
	rate := flag.Float64("rate", 0, "events per second (0 = unthrottled)")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "replay: --file is required")
		os.Exit(2)
	}

	in := os.Stdin
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "replay: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}

	// Anchor synthesized timestamps at a fixed epoch so replay is deterministic
	// (no Date.now()); a real source would use wall-clock kernel timestamps.
	base := time.Unix(0, 0).UTC()
	rows, err := source.Read(in, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	var delay time.Duration
	if *rate > 0 {
		delay = time.Duration(float64(time.Second) / *rate)
	}
	for i, row := range rows {
		if delay > 0 && i > 0 {
			time.Sleep(delay)
		}
		if err := enc.Encode(row.Event); err != nil {
			fmt.Fprintf(os.Stderr, "replay: encode: %v\n", err)
			os.Exit(1)
		}
	}
}
