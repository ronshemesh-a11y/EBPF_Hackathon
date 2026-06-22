// Command server is the web entrypoint for exectrace: it reads Verdict NDJSON
// on stdin (from `report --json`, the scorer binary, or any verdict producer)
// and serves a live browser page that shows each verdict as it arrives.
//
//	... | server [--addr :8080]
//
// In-memory only (a ring buffer of recent verdicts); storage is a later step.
// Ingest is stdin for now — it becomes a network endpoint when we package for
// multiple agents.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"exectrace/internal/server"
	"exectrace/internal/store"
	"exectrace/internal/types"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "exectrace.db", "SQLite file for verdict history")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("server: open db: %v", err)
	}
	defer st.Close()

	srv := server.New(st)
	srv.SetLogf(func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "server: "+format+"\n", a...)
	})

	// Read verdicts off stdin in the background; the HTTP server runs in the
	// foreground. Each decoded verdict is published to connected browsers.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var v types.Verdict
			if err := json.Unmarshal(line, &v); err != nil {
				fmt.Fprintf(os.Stderr, "server: bad verdict: %v\n", err)
				continue
			}
			srv.Publish(v)
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "server: read: %v\n", err)
		}
		// stdin closed: keep serving so the browser can still view the backlog.
		fmt.Fprintln(os.Stderr, "server: input stream ended; page stays up")
	}()

	fmt.Fprintf(os.Stderr, "server: listening on http://localhost%s (db=%s)\n", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
}
