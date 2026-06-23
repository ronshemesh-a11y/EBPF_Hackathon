import { useMemo } from "react";
import type { FeedItem } from "../lib/types";

// Terminal dark palette — these are raw hex because they live in the dark
// terminal surface, not the Upwind light theme.
const PROMPT_GREEN = "#56C38A";
const PROMPT_MUTED = "#5E6A7A";
const CMD_DEFAULT = "#C9D3E0";
const CMD_SUSPICIOUS = "#FFB070";
const CMD_MALICIOUS = "#FF9A88";
const FLAGGED_CORAL = "#EC6850";

const TERMINAL_ROWS = 20;

export function Terminal({ items, connected }: { items: FeedItem[]; connected: boolean }) {
  // Show the last N items in chronological order (oldest → newest = top → bottom)
  const rows = useMemo(() => [...items].slice(0, TERMINAL_ROWS).reverse(), [items]);

  return (
    <div style={{
      flexShrink: 0,
      height: "206px",
      background: "#141A24",
      borderTop: "1px solid var(--border-subtle)",
      display: "flex",
      flexDirection: "column",
      fontFamily: "var(--font-mono-family)",
    }}>
      {/* Header bar */}
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "9px 16px",
        borderBottom: "1px solid rgba(255,255,255,0.08)",
        color: "#8B97A8",
        fontSize: "11px",
        flexShrink: 0,
      }}>
        <TerminalChevronIcon />
        <span style={{ letterSpacing: "0.04em", textTransform: "uppercase" }}>
          Terminal — last commands
        </span>
        <span style={{ color: PROMPT_MUTED }}>maya@ip-10-0-4-12</span>
        <span style={{ flex: 1 }} />
        <span style={{ display: "inline-flex", alignItems: "center", gap: "5px" }}>
          <span style={{
            width: "6px",
            height: "6px",
            borderRadius: "50%",
            background: connected ? "#1FA062" : "#5E6A7A",
          }} />
          {connected ? "streaming" : "offline"}
        </span>
      </div>

      {/* Body */}
      <div style={{
        flex: 1,
        overflowY: "auto",
        padding: "10px 16px",
        fontSize: "12.5px",
        lineHeight: 1.85,
        color: CMD_DEFAULT,
      }}>
        {rows.length === 0 ? (
          <div style={{ color: PROMPT_MUTED }}>waiting for live events…</div>
        ) : (
          rows.map((it) => {
            const band = (it.band || "").toUpperCase();
            const cmdColor =
              band === "HIGH" ? CMD_MALICIOUS : band === "GRAY" ? CMD_SUSPICIOUS : CMD_DEFAULT;
            return (
              <div key={it._id}>
                <span style={{ color: PROMPT_GREEN }}>maya@ip-10-0-4-12</span>
                <span style={{ color: PROMPT_MUTED }}>:~$</span>{" "}
                <span style={{ color: cmdColor }}>{it.command}</span>
                {band === "HIGH" && (
                  <span style={{ color: FLAGGED_CORAL, marginLeft: "10px" }}>● flagged malicious</span>
                )}
              </div>
            );
          })
        )}
        {/* Blinking cursor */}
        <div>
          <span style={{ color: PROMPT_GREEN }}>maya@ip-10-0-4-12</span>
          <span style={{ color: PROMPT_MUTED }}>:~$</span>{" "}
          <span
            className="uw-blink-cursor"
            style={{
              display: "inline-block",
              width: "8px",
              height: "15px",
              background: CMD_DEFAULT,
              verticalAlign: "-2px",
            }}
          />
        </div>
      </div>
    </div>
  );
}

function TerminalChevronIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#5697EA" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  );
}
