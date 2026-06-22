// Package source turns a labeled CSV corpus into a stream of Events. It is the
// bridge that lets the whole pipeline run on a benchmark corpus instead of live
// eBPF — but the output is plain types.Event, so nothing downstream can tell
// replay from a live kernel feed.
//
// CSV shape: process_name, command_line[, label]
// A header row is auto-detected and skipped. The label column is optional and
// is carried separately (Row.Label) so eval can use ground truth without the
// Event ever knowing about it.
package source

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"exectrace/internal/types"
)

// Row is one parsed CSV record: the Event plus the optional ground-truth label.
type Row struct {
	Event types.Event
	Label string // "" if the corpus has no label column
}

// argv splitting is intentionally simple (whitespace + basic quote handling):
// the corpus stores already-typed command lines, not shell-escaped blobs.
func splitArgv(cmd string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}
	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return args
}

func looksLikeHeader(rec []string) bool {
	if len(rec) == 0 {
		return false
	}
	first := strings.ToLower(strings.TrimSpace(rec[0]))
	return first == "process_name" || first == "comm" || first == "process"
}

// Read parses the whole CSV into Rows. baseTs anchors the synthesized
// timestamps (caller supplies it so the parser stays free of Date.now()-style
// nondeterminism); each row is spaced 1ms apart. Pids are synthesized
// sequentially starting at 1000.
func Read(r io.Reader, baseTs time.Time) ([]Row, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate 2- or 3-column rows
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true // command lines contain bare inner quotes

	var rows []Row
	pid := 1000
	for i := 0; ; i++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv read row %d: %w", i, err)
		}
		if i == 0 && looksLikeHeader(rec) {
			continue
		}
		if len(rec) < 2 {
			return nil, fmt.Errorf("row %d: need at least process_name,command_line (got %d cols)", i, len(rec))
		}
		comm := strings.TrimSpace(rec[0])
		cmdLine := strings.TrimSpace(rec[1])
		label := ""
		if len(rec) >= 3 {
			label = strings.TrimSpace(rec[2])
		}

		argv := splitArgv(cmdLine)
		if len(argv) == 0 {
			argv = []string{comm}
		}

		rows = append(rows, Row{
			Event: types.Event{
				Ts:   baseTs.Add(time.Duration(len(rows)) * time.Millisecond),
				Type: "exec",
				Pid:  pid,
				Ppid: 1,
				Uid:  0,
				Comm: comm,
				Argv: argv,
			},
			Label: label,
		})
		pid++
	}
	return rows, nil
}

// CommandLine reconstructs a human-readable command string from an Event's
// argv. Used by the scorer and reporter so they share one rendering.
func CommandLine(e types.Event) string {
	return strings.Join(e.Argv, " ")
}
