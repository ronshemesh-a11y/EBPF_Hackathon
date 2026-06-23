import type { Metrics } from "../lib/useVerdicts";

export function SeveritySummary({ metrics }: { metrics: Metrics }) {
  const { perBand, total } = metrics;
  const malicious = perBand.HIGH;
  const suspicious = perBand.GRAY;
  const benign = perBand.LOW;

  // Proportion bar widths as percentages
  const maliciousPct = total > 0 ? (malicious / total) * 100 : 0;
  const suspiciousPct = total > 0 ? (suspicious / total) * 100 : 0;
  const benignPct = total > 0 ? Math.max(0, 100 - maliciousPct - suspiciousPct) : 0;

  return (
    <div style={{ marginBottom: 0 }}>
      <div style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "8px",
        boxShadow: "var(--shadow-sm)",
      }}>
        {/* Header */}
        <div style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          padding: "14px 16px",
          borderBottom: "1px solid var(--border-subtle)",
        }}>
          <div>
            <div style={{ fontSize: "14px", fontWeight: 500, color: "var(--text-primary)" }}>Summary by severity</div>
            <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
              {total} commands · live session
            </div>
          </div>
        </div>
        <div style={{ padding: "16px" }}>
          {/* Proportion bar */}
          <div style={{ display: "flex", gap: "2px", height: "8px", marginBottom: "18px" }}>
            {maliciousPct > 0 && (
              <div style={{
                width: `${maliciousPct}%`,
                background: "var(--severity-critical)",
                borderRadius: suspiciousPct === 0 && benignPct === 0 ? "50px" : "50px 0 0 50px",
                minWidth: "4px",
              }} title="malicious" />
            )}
            {suspiciousPct > 0 && (
              <div style={{
                width: `${suspiciousPct}%`,
                background: "var(--severity-medium)",
                borderRadius: maliciousPct === 0 ? "50px 0 0 50px" : benignPct === 0 ? "0 50px 50px 0" : "0",
                minWidth: "4px",
              }} title="suspicious" />
            )}
            {benignPct > 0 && (
              <div style={{
                flex: 1,
                background: "var(--severity-low)",
                borderRadius: maliciousPct === 0 && suspiciousPct === 0 ? "50px" : "0 50px 50px 0",
                minWidth: "4px",
              }} title="benign" />
            )}
            {total === 0 && (
              <div style={{ flex: 1, background: "var(--border-subtle)", borderRadius: "50px" }} />
            )}
          </div>

          {/* Rows */}
          <SummaryRow
            letter="C"
            letterFg="var(--severity-critical)"
            letterBg="var(--severity-critical-bg)"
            name="Malicious"
            descriptor="scripts piped to shell, untrusted fetches"
            count={malicious}
          />
          <SummaryRow
            letter="M"
            letterFg="var(--severity-medium)"
            letterBg="var(--severity-medium-bg)"
            name="Suspicious"
            descriptor="permission changes, listeners, remote pulls"
            count={suspicious}
          />
          <SummaryRow
            letter="L"
            letterFg="var(--uw-yellow-01)"
            letterBg="var(--severity-low-bg)"
            name="Benign"
            descriptor="routine admin, build & deploy commands"
            count={benign}
            last
          />
        </div>
      </div>
    </div>
  );
}

function SummaryRow({
  letter,
  letterFg,
  letterBg,
  name,
  descriptor,
  count,
  last,
}: {
  letter: string;
  letterFg: string;
  letterBg: string;
  name: string;
  descriptor: string;
  count: number;
  last?: boolean;
}) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: "12px",
      padding: "9px 0",
      borderBottom: last ? "none" : "1px solid var(--bg-tertiary)",
    }}>
      <span style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: "22px",
        height: "22px",
        borderRadius: "4px",
        background: letterBg,
        color: letterFg,
        fontSize: "12px",
        fontWeight: 700,
        flexShrink: 0,
      }}>
        {letter}
      </span>
      <span style={{ fontSize: "13px", fontWeight: 500, color: "var(--text-primary)" }}>{name}</span>
      <span style={{ fontSize: "12px", color: "var(--text-tertiary)" }}>{descriptor}</span>
      <span style={{ flex: 1 }} />
      <span style={{
        fontSize: "15px",
        fontWeight: 500,
        color: "var(--text-primary)",
        fontFamily: "var(--font-mono-family)",
      }}>
        {count}
      </span>
    </div>
  );
}
