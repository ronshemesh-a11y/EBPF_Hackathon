import { Zap, Cpu, Database } from "lucide-react";

// SourceChip shows where a verdict came from — a burst of `cache` hits is the
// speed story (instant), `llm` is a fresh model call. If latency_ms is present
// (P2 adds it), it renders "N ms" too. Colors from Upwind variables only.
function meta(source: string): { label: string; fg: string; bg: string; icon: React.ReactNode } {
  switch ((source || "").toLowerCase()) {
    case "cache":
      return {
        label: "cache",
        fg: "var(--severity-safe)",
        bg: "var(--severity-safe-bg)",
        icon: <Database size={11} />,
      };
    case "llm":
      return {
        label: "llm",
        fg: "var(--action-primary)",
        bg: "var(--severity-info-bg)",
        icon: <Cpu size={11} />,
      };
    case "error":
      return {
        label: "error",
        fg: "var(--severity-medium)",
        bg: "var(--severity-medium-bg)",
        icon: <Zap size={11} />,
      };
    default: // rule, or anything else
      return {
        label: source || "—",
        fg: "var(--text-tertiary)",
        bg: "var(--bg-secondary)",
        icon: null,
      };
  }
}

export function SourceChip({
  source,
  latencyMs,
  compact,
}: {
  source: string;
  latencyMs?: number;
  compact?: boolean;
}) {
  if (!source) return null;
  const m = meta(source);
  return (
    <span
      className="shrink-0 inline-flex items-center gap-4 rounded-4 px-4 font-mono"
      style={{ color: m.fg, background: m.bg, fontSize: "10px", fontWeight: 500, lineHeight: "16px" }}
      title={latencyMs !== undefined ? `scored in ${latencyMs} ms` : `source: ${m.label}`}
    >
      {!compact && m.icon}
      {m.label}
      {latencyMs !== undefined && <span style={{ opacity: 0.85 }}>{latencyMs}ms</span>}
    </span>
  );
}
