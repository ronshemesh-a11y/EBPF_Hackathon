import type { Metrics } from "../lib/useVerdicts";

export function MetricCards({ metrics }: { metrics: Metrics }) {
  const { perBand, total } = metrics;
  const benign = perBand.LOW;
  const benignPct = total > 0 ? ((benign / total) * 100).toFixed(1) : "0.0";

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "16px",
      marginBottom: "16px",
    }}>
      <MetricCard
        label="Malicious"
        letter="C"
        letterFg="var(--severity-critical)"
        letterBg="var(--severity-critical-bg)"
        value={perBand.HIGH}
        valueFg="var(--severity-critical)"
        subline={perBand.HIGH > 0 ? `▲ ${perBand.HIGH} needs review` : "none detected"}
        sublineFg={perBand.HIGH > 0 ? "var(--severity-critical)" : "var(--text-tertiary)"}
      />
      <MetricCard
        label="Suspicious"
        letter="M"
        letterFg="var(--severity-medium)"
        letterBg="var(--severity-medium-bg)"
        value={perBand.GRAY}
        valueFg="var(--severity-medium)"
        subline={perBand.GRAY > 0 ? "flagged for context" : "none flagged"}
        sublineFg="var(--text-secondary)"
      />
      <MetricCard
        label="Benign"
        letter="L"
        letterFg="var(--uw-yellow-01)"
        letterBg="var(--severity-low-bg)"
        value={benign}
        valueFg="var(--severity-safe)"
        subline={`${benignPct}% of traffic`}
        sublineFg="var(--text-secondary)"
      />
    </div>
  );
}

function MetricCard({
  label,
  letter,
  letterFg,
  letterBg,
  value,
  valueFg,
  subline,
  sublineFg,
}: {
  label: string;
  letter: string;
  letterFg: string;
  letterBg: string;
  value: number;
  valueFg: string;
  subline: string;
  sublineFg: string;
}) {
  return (
    <div style={{
      background: "var(--surface-card)",
      border: "1px solid var(--border-subtle)",
      borderRadius: "8px",
      boxShadow: "var(--shadow-sm)",
      padding: "16px",
      display: "flex",
      flexDirection: "column",
      gap: "10px",
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
        <span style={{ fontSize: "12px", fontWeight: 500, color: "var(--text-secondary)" }}>{label}</span>
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          width: "18px",
          height: "18px",
          borderRadius: "4px",
          background: letterBg,
          color: letterFg,
          fontSize: "11px",
          fontWeight: 700,
        }}>
          {letter}
        </span>
      </div>
      <span style={{ fontSize: "30px", fontWeight: 500, lineHeight: 1, letterSpacing: "-0.01em", color: valueFg }}>
        {value}
      </span>
      <span style={{ fontSize: "12px", fontWeight: 500, color: sublineFg }}>
        {subline}
      </span>
    </div>
  );
}
