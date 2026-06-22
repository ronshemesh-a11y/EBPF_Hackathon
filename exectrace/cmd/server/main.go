// Command server is the web entrypoint for exectrace: it reads Verdict NDJSON
// on stdin and serves a live browser page that shows each verdict as it
// arrives. Every row on screen corresponds to a verdict that came up the pipe
// — there is no seeded or sample data.
//
// Live path (real eBPF sensor + real LLM):
//
//	sudo ./bin/execguard | ./bin/report --scorer llm --json | ./bin/server
//
// The --ingest label is descriptive (the server can't see past its own stdin);
// set it to record what's actually upstream in the startup log and DB name.
// Keep replay/mockp2/testdata for eval and offline dev — never wire them here.
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
	dbPath := flag.String("db", "exectrace-live.db", "SQLite file for verdict history (live stream only; never seed from testdata)")
	ingest := flag.String("ingest", "live execguard · scorer: llm", "descriptive label for what's upstream (shown in startup log)")
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

	fmt.Fprintf(os.Stderr, "server: ingest: %s\n", *ingest)
	fmt.Fprintf(os.Stderr, "server: listening on http://localhost%s (db=%s)\n", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
}
