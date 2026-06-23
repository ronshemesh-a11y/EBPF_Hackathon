// Verdict mirrors Go's types.Verdict JSON exactly — the API contract. The
// frontend only renders it; it never reshapes the contract.
export interface Verdict {
  pid: number;
  ppid?: number; // present on richer (eBPF) events; used for the process tree
  command: string;
  score: number;
  band: string; // LOW | GRAY | HIGH
  verdict: string; // benign | suspicious | malicious | unknown | error
  reason: string;
  mitre: string[] | null;
  tactic: string;
  source: string; // rule | llm | cache | error
  ts: string; // RFC3339
  // Optional: time the scorer spent on this command. P2 already times the LLM
  // call — this lights up "scored in N ms" the moment they add the field. A
  // cache hit is ~0 ms; an llm call is hundreds. We render it only if present.
  latency_ms?: number;
}

// A verdict tagged with a stable client-side id + arrival order, so React keys
// and selection survive re-renders even when pids repeat.
export interface FeedItem extends Verdict {
  _id: string;
  _seq: number;
  _live: boolean; // arrived over the websocket (vs loaded from history) → animate
}

// AggregatedItem groups repeated executions of the same command into one row.
// The right-drawer live feed shows one row per unique command text plus ×N count.
export interface AggregatedItem {
  cmd: string;
  verdict: string;
  band: string;
  count: number;
  lastSeen: string; // RFC3339 of most recent occurrence
  item: FeedItem;   // the most recent raw item (for opening detail modal)
}
