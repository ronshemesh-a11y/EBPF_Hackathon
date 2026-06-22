// fmtTime renders an RFC3339 timestamp as HH:MM:SS.mmm (24h). Falls back to the
// raw string if unparseable (e.g. the replay corpus's fixed-epoch demo data).
export function fmtTime(ts: string): string {
  const d = ts ? new Date(ts) : new Date();
  if (isNaN(d.getTime())) return ts || "";
  const hms = d.toLocaleTimeString("en-GB", { hour12: false });
  return `${hms}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}
