package main

import "sync"

// queue is a bounded, drop-oldest FIFO of pending exec events feeding the worker
// pool. The stdin reader Pushes at full speed and never blocks, so the kernel
// ring buffer upstream stays drained; when the queue is full the OLDEST unscored
// event is evicted and counted, so backpressure never reaches the kernel.
// Workers block in Pop until an event is available or the queue is closed.
//
// Backed by a fixed ring buffer (head + count) rather than a re-sliced slice, so
// a long-running process never leaks the backing array.
type queue struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	buf      []ExecEvent
	head     int   // index of the oldest element
	count    int   // number of elements currently buffered
	seq      int   // monotonic sequence assigned at Pop (input order of survivors)
	closed   bool
	dropped  int64
}

// newQueue returns a queue holding at most capacity pending events.
func newQueue(capacity int) *queue {
	if capacity < 1 {
		capacity = 1
	}
	q := &queue{buf: make([]ExecEvent, capacity)}
	q.notEmpty = sync.NewCond(&q.mu)
	return q
}

// Push appends ev, evicting the oldest element if the queue is full. Never blocks.
func (q *queue) Push(ev ExecEvent) {
	q.mu.Lock()
	if q.count == len(q.buf) {
		q.head = (q.head + 1) % len(q.buf) // drop oldest to make room
		q.count--
		q.dropped++
	}
	q.buf[(q.head+q.count)%len(q.buf)] = ev
	q.count++
	q.mu.Unlock()
	q.notEmpty.Signal()
}

// Pop returns the next event in FIFO order tagged with a monotonic seq, blocking
// until one is available. ok is false once the queue is closed and drained.
//
// seq is assigned here (not at Push) so that drop-evicted events never consume a
// sequence number — the ordered writer keys on contiguous seqs and would stall
// forever waiting on a seq that was dropped before scoring.
func (q *queue) Pop() (seq int, ev ExecEvent, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.count == 0 && !q.closed {
		q.notEmpty.Wait()
	}
	if q.count == 0 {
		return 0, ExecEvent{}, false
	}
	ev = q.buf[q.head]
	q.buf[q.head] = ExecEvent{} // release the reference for GC
	q.head = (q.head + 1) % len(q.buf)
	q.count--
	seq = q.seq
	q.seq++
	return seq, ev, true
}

// Close marks the queue closed and wakes every blocked worker so they drain the
// remainder and exit.
func (q *queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.notEmpty.Broadcast()
}

// Dropped returns the number of events evicted due to overflow.
func (q *queue) Dropped() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}
