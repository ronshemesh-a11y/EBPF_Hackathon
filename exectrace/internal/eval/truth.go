package eval

import (
	"bufio"
	"io"
	"strings"
)

// NormalizeCmd collapses internal whitespace runs to single spaces and trims
// the ends, so that command lines differing only in spacing match.
func NormalizeCmd(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// TruthSet is a set of malicious command lines, matched after normalization.
type TruthSet struct {
	cmds map[string]struct{}
}

// LoadTruth parses a ground-truth file: one malicious command_line per line,
// blank lines and lines beginning with '#' ignored, matched
// whitespace-normalized.
func LoadTruth(r io.Reader) (*TruthSet, error) {
	ts := &TruthSet{cmds: map[string]struct{}{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ts.cmds[NormalizeCmd(line)] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ts, nil
}

// Label returns "malicious" if cmd is in the truth set, else "benign". This
// lets a TruthSet stand in for the label column: a command present in the file
// is a positive, everything else is a negative.
func (t *TruthSet) Label(cmd string) string {
	if _, ok := t.cmds[NormalizeCmd(cmd)]; ok {
		return "malicious"
	}
	return "benign"
}

// Len reports how many distinct malicious commands are in the set.
func (t *TruthSet) Len() int { return len(t.cmds) }
