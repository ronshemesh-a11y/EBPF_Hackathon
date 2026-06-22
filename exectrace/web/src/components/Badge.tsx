import { severity } from "../lib/severity";

// SeverityBadge renders a band as an Upwind severity pill — fg/bg from tokens.
export function SeverityBadge({ band }: { band: string }) {
  const s = severity(band);
  return (
    <span
      className="inline-flex items-center rounded-4 px-8 font-mono"
      style={{
        color: s.fg,
        background: s.bg,
        fontSize: "11px",
        fontWeight: 500,
        lineHeight: "18px",
        letterSpacing: "0.02em",
      }}
    >
      {(band || "?").toUpperCase()}
    </span>
  );
}

// MitreTags renders MITRE technique IDs as subtle mono chips.
export function MitreTags({ mitre }: { mitre: string[] | null }) {
  if (!mitre || mitre.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-4">
      {mitre.map((m) => (
        <span
          key={m}
          className="rounded-4 font-mono"
          style={{
            background: "var(--bg-secondary)",
            color: "var(--text-tertiary)",
            border: "1px solid var(--border-subtle)",
            fontSize: "11px",
            padding: "0 6px",
            lineHeight: "16px",
          }}
        >
          {m}
        </span>
      ))}
    </span>
  );
}
