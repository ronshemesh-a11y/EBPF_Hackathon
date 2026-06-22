package main

import (
	"sync"
	"testing"
)

// ev builds an ExecEvent whose command line is a single marker arg, so FIFO
// order is easy to assert.
func ev(tag string) ExecEvent {
	return ExecEvent{Executable: "/bin/x", Argv: []string{tag}}
}

func TestQueueFIFOOrderAndSeq(t *testing.T) {
	q := newQueue(8)
	for _, tag := range []string{"a", "b", "c"} {
		q.Push(ev(tag))
	}
	want := []struct {
		seq int
		tag string
	}{{0, "a"}, {1, "b"}, {2, "c"}}
	for _, w := range want {
		seq, e, ok := q.Pop()
		if !ok {
			t.Fatalf("Pop returned ok=false early")
		}
		if seq != w.seq || e.Argv[0] != w.tag {
			t.Fatalf("got seq=%d tag=%s, want seq=%d tag=%s", seq, e.Argv[0], w.seq, w.tag)
		}
	}
}

func TestQueueDropsOldestWhenFull(t *testing.T) {
	q := newQueue(3)
	for _, tag := range []string{"a", "b", "c", "d", "e"} { // 2 over capacity
		q.Push(ev(tag))
	}
	if got := q.Dropped(); got != 2 {
		t.Fatalf("Dropped()=%d, want 2", got)
	}
	// Survivors must be the 3 newest, in order: c, d, e.
	var got []string
	q.Close()
	for {
		_, e, ok := q.Pop()
		if !ok {
			break
		}
		got = append(got, e.Argv[0])
	}
	want := []string{"c", "d", "e"}
	if len(got) != len(want) {
		t.Fatalf("survivors=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("survivors=%v, want %v", got, want)
		}
	}
}

func TestQueuePopAfterCloseDrainsThenStops(t *testing.T) {
	q := newQueue(4)
	q.Push(ev("a"))
	q.Close()
	if _, _, ok := q.Pop(); !ok {
		t.Fatalf("Pop should drain the buffered item after Close")
	}
	if _, _, ok := q.Pop(); ok {
		t.Fatalf("Pop should return ok=false once closed and empty")
	}
}

func TestQueuePopBlocksUntilPush(t *testing.T) {
	q := newQueue(4)
	var wg sync.WaitGroup
	wg.Add(1)
	got := make(chan string, 1)
	go func() {
		defer wg.Done()
		_, e, ok := q.Pop() // blocks until the Push below
		if ok {
			got <- e.Argv[0]
		}
	}()
	q.Push(ev("z"))
	wg.Wait()
	if g := <-got; g != "z" {
		t.Fatalf("blocked Pop got %q, want z", g)
	}
}
