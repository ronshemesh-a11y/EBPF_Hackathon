import type { FeedItem } from "../lib/types";
import { severity } from "../lib/severity";
import { fmtTime } from "../lib/format";

export function DetailModal({ item, onClose }: { item: FeedItem; onClose: () => void }) {
  const s = severity(item.band);

  // Split command into executable and arguments for display
  const parts = (item.command || "").trim().split(/\s+/);
  const executable = parts[0] || "";
  const args = parts.slice(1).join(" ");

  // Parse "why flagged" bullets from the reason field
  const bullets = item.reason
    ? item.reason
        .split(/[.;]/)
        .map((b) => b.trim())
        .filter(Boolean)
    : [];

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 80,
        background: "rgba(24,32,45,0.42)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "24px",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "520px",
          maxWidth: "100%",
          background: "var(--surface-card)",
          borderRadius: "12px",
          boxShadow: "0 20px 40px -10px rgba(0,0,0,0.3)",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "16px 20px",
          borderBottom: "1px solid var(--border-subtle)",
        }}>
          <span style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: "24px",
            height: "24px",
            borderRadius: "4px",
            background: s.bg,
            color: s.badgeFg,
            fontSize: "13px",
            fontWeight: 700,
          }}>
            {s.letter}
          </span>
          <span style={{ fontSize: "16px", fontWeight: 500, color: "var(--text-primary)" }}>
            {s.label.charAt(0).toUpperCase() + s.label.slice(1)} command
          </span>
          {/* Severity pill */}
          <span style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "5px",
            height: "20px",
            padding: "0 8px",
            borderRadius: "4px",
            fontSize: "11px",
            fontWeight: 500,
            color: s.fg,
            background: s.bg,
          }}>
            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: s.fg }} />
            {item.verdict || "unknown"}
          </span>
          <span style={{ flex: 1 }} />
          <button
            onClick={onClose}
            className="uw-icon-btn"
            style={{
              width: "28px",
              height: "28px",
              border: "none",
              background: "transparent",
              borderRadius: "6px",
              color: "var(--text-secondary)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
            }}
          >
            <CloseIcon />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "20px" }}>
          {/* Full command in dark code block */}
          <div style={{
            background: "#141A24",
            borderRadius: "6px",
            padding: "12px 14px",
            fontFamily: "var(--font-mono-family)",
            fontSize: "13px",
            color: "#FF9A88",
            wordBreak: "break-all",
          }}>
            <span style={{ color: "#5E6A7A" }}>$ </span>
            {item.command}
          </div>

          {/* Metadata grid */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "14px 20px",
            marginTop: "18px",
          }}>
            <ModalField label="File name">
              <span style={{ fontFamily: "var(--font-mono-family)", fontSize: "13px", color: "var(--text-primary)" }}>
                {executable.split("/").pop() || executable}
              </span>
            </ModalField>
            <ModalField label="Time">
              <span style={{ fontFamily: "var(--font-mono-family)", fontSize: "13px", color: "var(--text-primary)" }}>
                {fmtTime(item.ts)} UTC
              </span>
            </ModalField>
            {args && (
              <div style={{ gridColumn: "1 / -1" }}>
                <ModalField label="Arguments">
                  <span style={{
                    fontFamily: "var(--font-mono-family)",
                    fontSize: "13px",
                    color: "var(--text-primary)",
                    wordBreak: "break-all",
                  }}>
                    {args}
                  </span>
                </ModalField>
              </div>
            )}
          </div>

          {/* Why flagged */}
          {bullets.length > 0 && (
            <>
              <div style={{
                fontSize: "11px",
                color: "var(--text-tertiary)",
                textTransform: "uppercase",
                letterSpacing: "0.04em",
                margin: "20px 0 8px",
              }}>
                Why flagged
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {bullets.map((bullet, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", fontSize: "13px", color: "var(--text-primary)" }}>
                    <span style={{
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: s.fg,
                      flexShrink: 0,
                    }} />
                    {bullet}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{
          display: "flex",
          justifyContent: "flex-end",
          padding: "14px 20px",
          borderTop: "1px solid var(--border-subtle)",
          background: "var(--bg-secondary)",
        }}>
          <button
            onClick={onClose}
            className="uw-btn-ghost"
            style={{
              padding: "8px 14px",
              border: "1px solid var(--border-subtle)",
              background: "var(--surface-card)",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: 500,
              color: "var(--text-primary)",
              cursor: "pointer",
            }}
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}

function ModalField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{
        fontSize: "11px",
        color: "var(--text-tertiary)",
        textTransform: "uppercase",
        letterSpacing: "0.04em",
        marginBottom: "3px",
      }}>
        {label}
      </div>
      {children}
    </div>
  );
}

function CloseIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
