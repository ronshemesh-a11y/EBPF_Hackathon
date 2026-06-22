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
}

// A verdict tagged with a stable client-side id + arrival order, so React keys
// and selection survive re-renders even when pids repeat.
export interface FeedItem extends Verdict {
  _id: string;
  _seq: number;
}
