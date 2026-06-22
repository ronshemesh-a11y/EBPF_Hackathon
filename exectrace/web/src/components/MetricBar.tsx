import { ShieldAlert, Zap } from "lucide-react";
import type { Metrics } from "../lib/useVerdicts";
import { severity } from "../lib/severity";
import { Sparkline } from "./Sparkline";

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

// Throughput is the hero stat: a big events/sec number with a live pulse dot and
// a 60s sparkline, so the demo visibly races.
function ThroughputHero({ m }: { m: Metrics }) {
  const live = m.connected && m.eventsPerSec > 0;
  return (
    <div
      className="flex items-center gap-12 rounded-8 px-16"
      style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-subtle)",
        height: "36px",
      }}
    >
      <span
        className={live ? "uw-pulse-dot" : ""}
        style={{
          width: 8,
          height: 8,
          borderRadius: "var(--radius-circle)",
          background: live ? "var(--action-primary)" : "var(--text-tertiary)",
        }}
      />
      <div className="flex items-baseline gap-4">
        <span
          className="font-mono"
          style={{ color: "var(--action-primary)", fontSize: "22px", fontWeight: 700, lineHeight: 1 }}
        >
          {m.eventsPerSec.toFixed(1)}
        </span>
        <span className="font-mono" style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
          /s
        </span>
      </div>
      <span className="uw-body-sm" style={{ color: "var(--text-tertiary)" }}>
        events
      </span>
      <Sparkline values={m.epsHistory} />
    </div>
  );
}

// Scored total — a running counter that visibly climbs as commands flow.
function ScoredTotal({ n }: { n: number }) {
  return (
    <div
      className="flex items-center gap-8 rounded-8 px-12"
      style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-subtle)",
        height: "36px",
      }}
    >
      <span className="uw-body-sm" style={{ color: "var(--text-secondary)" }}>
        scored
      </span>
      <span
        className="font-mono tabular-nums"
        style={{ color: "var(--text-primary)", fontSize: "16px", fontWeight: 700 }}
      >
        {n.toLocaleString()}
      </span>
    </div>
  );
}

// MetricBar is the top row of live KPI chips. latencyMs is optional (model
// latency only appears when a producer reports it).
export function MetricBar({ m, latencyMs }: { m: Metrics; latencyMs?: number }) {
  return (
    <div className="flex items-center gap-12 flex-wrap">
      <ThroughputHero m={m} />
      <ScoredTotal n={m.total} />
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
    </div>
  );
}
