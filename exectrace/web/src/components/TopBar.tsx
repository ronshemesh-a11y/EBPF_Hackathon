import { Logo } from "./Logo";
import type { Metrics } from "../lib/useVerdicts";

const SCOPE_HOST = "ip-10-0-4-12";

export function TopBar({ metrics }: { metrics: Metrics }) {
  const live = metrics.connected;
  return (
    <header
      style={{
        height: "var(--upwind-header-height)",
        flexShrink: 0,
        background: "var(--surface-card)",
        borderBottom: "1px solid var(--border-subtle)",
        display: "flex",
        alignItems: "center",
        gap: "12px",
        padding: "0 16px",
        position: "relative",
        zIndex: 30,
      }}
    >
      {/* Left: logo + chip + divider + scope */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", flexShrink: 0 }}>
        <Logo size={20} />
        <span style={{
          fontFamily: "var(--font-mono-family)",
          fontSize: "11px",
          fontWeight: 500,
          letterSpacing: "0.04em",
          color: "var(--text-tertiary)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-4)",
          padding: "1px 6px",
          textTransform: "uppercase",
        }}>
          exectrace
        </span>
        <div style={{ width: "1px", height: "24px", background: "var(--border-subtle)" }} />
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          padding: "6px 10px",
          border: "1px solid var(--border-subtle)",
          borderRadius: "6px",
          fontSize: "13px",
          color: "var(--text-primary)",
          background: "var(--surface-card)",
        }}>
          <ServerIcon />
          <span style={{ fontFamily: "var(--font-mono-family)", fontSize: "12px" }}>{SCOPE_HOST}</span>
          <ChevronIcon />
        </div>
      </div>

      {/* Center: search */}
      <div style={{ flex: 1, display: "flex", justifyContent: "center", minWidth: 0 }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          width: "100%",
          maxWidth: "460px",
          height: "34px",
          padding: "0 8px 0 12px",
          background: "var(--bg-secondary)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "6px",
          cursor: "text",
        }}>
          <SearchIcon />
          <span style={{ flex: 1, fontSize: "13px", color: "var(--text-tertiary)" }}>
            Search commands, verdicts, PIDs…
          </span>
          <kbd style={{
            fontFamily: "var(--font-mono-family)",
            fontSize: "11px",
            color: "var(--text-secondary)",
            background: "var(--surface-card)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "var(--radius-4)",
            padding: "1px 6px",
          }}>
            ⌘K
          </kbd>
        </div>
      </div>

      {/* Right: live pill + bell + divider + avatar */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        {live ? (
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "4px 11px",
            borderRadius: "50px",
            background: "var(--uw-green-05)",
            color: "var(--uw-green-01)",
            fontSize: "12px",
            fontWeight: 500,
          }}>
            <span className="uw-pulse-dot" style={{
              width: "7px",
              height: "7px",
              borderRadius: "50%",
              background: "var(--uw-green-02)",
            }} />
            Live
          </div>
        ) : (
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "4px 11px",
            borderRadius: "50px",
            background: "var(--bg-tertiary)",
            color: "var(--text-secondary)",
            fontSize: "12px",
            fontWeight: 500,
          }}>
            <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--text-tertiary)" }} />
            Paused
          </div>
        )}
        <button className="uw-icon-btn" title="Notifications" style={{
          width: "34px",
          height: "34px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "none",
          background: "transparent",
          borderRadius: "6px",
          cursor: "pointer",
          color: "var(--text-secondary)",
        }}>
          <BellIcon />
        </button>
        <div style={{ width: "1px", height: "24px", background: "var(--border-subtle)" }} />
        <div style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer" }}>
          <div style={{
            width: "30px",
            height: "30px",
            borderRadius: "50%",
            background: "var(--action-primary)",
            color: "var(--text-inverse)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "12px",
            fontWeight: 600,
          }}>
            MR
          </div>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontSize: "13px", fontWeight: 500, color: "var(--text-primary)" }}>Maya Rosen</span>
            <span style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>Acme Corp</span>
          </div>
          <ChevronIcon />
        </div>
      </div>
    </header>
  );
}

function ServerIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="6" rx="1" />
      <rect x="2" y="15" width="20" height="6" rx="1" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}
function ChevronIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}
function BellIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}
