// Verdict mirrors Go's unified types.Verdict JSON exactly — the API contract.
// The frontend only renders it; it never reshapes the contract. The minimal P1
// sensor carries no per-process identity, so there is no pid/ppid here.
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
}

// A verdict tagged with a stable client-side id + arrival order, so React keys
// and selection survive re-renders.
export interface FeedItem extends Verdict {
  _id: string;
  _seq: number;
}
