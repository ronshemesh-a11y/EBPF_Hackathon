// Verdict mirrors Go's unified types.Verdict JSON exactly — the API contract.
// The frontend only renders it; it never reshapes the contract. The sensor now
// carries per-process provenance (read from task_struct), all optional.
export interface Verdict {
  executable: string;
  command: string;
  risk_score: number;
  band: string; // LOW | GRAY | HIGH
  verdict: string; // benign | suspicious | malicious | error
  reason: string;
  mitre: string[] | null;
  risk_indicators: string[] | null;
  source: string; // rule | llm | cache | error
  ts: string; // RFC3339
  // Provenance from the sensor (task_struct); minimal/replayed events omit them.
  // comm is the acting (pre-exec/spawner) name; parent_comm its parent.
  pid?: number;
  ppid?: number;
  comm?: string;
  parent_comm?: string;
}

// A verdict tagged with a stable client-side id + arrival order, so React keys
// and selection survive re-renders. _count collapses repeated identical rows.
export interface FeedItem extends Verdict {
  _id: string;
  _seq: number;
  _count?: number;
}
