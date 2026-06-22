import { Activity, ShieldAlert, Zap } from "lucide-react";
import type { Metrics } from "../lib/useVerdicts";
import { severity } from "../lib/severity";

function Chip({
  label,
  value,
  accent,
  icon,
}: {
  label: string;
  value: string;
  accent?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div
      className="flex items-center gap-8 rounded-8 px-12"
      style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-subtle)",
        height: "36px",
      }}
    >
      {icon && <span style={{ color: accent ?? "var(--text-tertiary)" }}>{icon}</span>}
      <span className="uw-body-sm" style={{ color: "var(--text-secondary)" }}>
        {label}
      </span>
      <span
        className="font-mono"
        style={{ color: accent ?? "var(--text-primary)", fontSize: "14px", fontWeight: 500 }}
      >
        {value}
      </span>
    </div>
  );
}

function BandCount({ band, n }: { band: "HIGH" | "GRAY" | "LOW"; n: number }) {
  const s = severity(band);
  return (
    <div
      className="flex items-center gap-8 rounded-8 px-12"
      style={{ background: s.bg, height: "36px" }}
    >
      <span style={{ color: s.fg, fontSize: "12px", fontWeight: 500 }}>{s.label}</span>
      <span className="font-mono" style={{ color: s.fg, fontSize: "14px", fontWeight: 700 }}>
        {n}
      </span>
    </div>
  );
}

// MetricBar is the top row of live KPI chips. latencyMs is optional (model
// latency only appears when a producer reports it).
export function MetricBar({ m, latencyMs }: { m: Metrics; latencyMs?: number }) {
  return (
    <div className="flex items-center gap-12 flex-wrap">
      <Chip
        label="events/sec"
        value={m.eventsPerSec.toFixed(1)}
        icon={<Activity size={15} />}
        accent="var(--action-primary)"
      />
      <Chip
        label="flagged"
        value={`${m.flaggedPct.toFixed(0)}%`}
        icon={<ShieldAlert size={15} />}
        accent={m.flaggedPct > 0 ? "var(--severity-medium)" : undefined}
      />
      <BandCount band="HIGH" n={m.perBand.HIGH} />
      <BandCount band="GRAY" n={m.perBand.GRAY} />
      <BandCount band="LOW" n={m.perBand.LOW} />
      {latencyMs !== undefined && (
        <Chip label="model latency" value={`${latencyMs} ms`} icon={<Zap size={15} />} />
      )}
      <Chip label="total" value={String(m.total)} />
    </div>
  );
}
