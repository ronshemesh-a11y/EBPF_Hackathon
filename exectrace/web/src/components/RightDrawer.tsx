import type { AggregatedItem, FeedItem } from "../lib/types";
import { severity } from "../lib/severity";
import { fmtTime } from "../lib/format";

export function RightDrawer({
  open,
  aggregated,
  onToggle,
  onSelect,
}: {
  open: boolean;
  aggregated: AggregatedItem[];
  onToggle: () => void;
  onSelect: (item: FeedItem) => void;
}) {
  return (
    <aside style={{
      flexShrink: 0,
      width: open ? "344px" : "0",
      minWidth: 0,
      background: "var(--surface-card)",
      borderLeft: open ? "1px solid var(--border-subtle)" : "none",
      overflow: "hidden",
      transition: "width 220ms ease",
      display: "flex",
      flexDirection: "column",
    }}>
      <div style={{ width: "344px", height: "100%", display: "flex", flexDirection: "column" }}>
        {/* Header */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          padding: "14px 16px",
          borderBottom: "1px solid var(--border-subtle)",
          flexShrink: 0,
        }}>
          <span style={{ fontSize: "14px", fontWeight: 500, color: "var(--text-primary)" }}>Live feed</span>
          <span style={{
            fontFamily: "var(--font-mono-family)",
            fontSize: "11px",
            fontWeight: 500,
            color: "var(--text-secondary)",
            background: "var(--bg-tertiary)",
            borderRadius: "var(--radius-pill)",
            padding: "1px 8px",
          }}>
            {aggregated.length} unique
          </span>
          <span style={{ flex: 1 }} />
          <button
            onClick={onToggle}
            className="uw-icon-btn"
            title="Collapse"
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
            <ChevronRightIcon />
          </button>
        </div>

        {/* Filter strip */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          padding: "8px 16px",
          borderBottom: "1px solid var(--border-subtle)",
          background: "var(--bg-secondary)",
          color: "var(--text-secondary)",
          fontSize: "11px",
          flexShrink: 0,
        }}>
          <FilterIcon />
          <span>
            Only <span style={{ fontFamily: "var(--font-mono-family)" }}>maya (uid 1000)</span> · system noise hidden · repeats aggregated
          </span>
        </div>

        {/* Feed rows */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {aggregated.length === 0 ? (
            <div style={{ padding: "24px 16px", fontSize: "12px", color: "var(--text-tertiary)" }}>
              waiting for live events…
            </div>
          ) : (
            aggregated.map(({ cmd, verdict, band, count, lastSeen, item }) => {
              const s = severity(band);
              return (
                <button
                  key={cmd}
                  onClick={() => onSelect(item)}
                  className="uw-drawer-row"
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "10px 16px",
                    borderBottom: "1px solid var(--bg-tertiary)",
                    background: "transparent",
                    border: "none",
                    borderBottomWidth: "1px",
                    borderBottomStyle: "solid",
                    borderBottomColor: "var(--bg-tertiary)",
                    textAlign: "left",
                    cursor: "pointer",
                  }}
                >
                  <span style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    flexShrink: 0,
                    background: s.fg,
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontFamily: "var(--font-mono-family)",
                      fontSize: "12.5px",
                      color: "var(--text-primary)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}>
                      {cmd}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "3px" }}>
                      <span style={{ fontSize: "11px", fontWeight: 500, color: s.fg }}>
                        {verdict || "unknown"}
                      </span>
                      <span style={{
                        fontFamily: "var(--font-mono-family)",
                        fontSize: "10px",
                        color: "var(--text-tertiary)",
                      }}>
                        {fmtTime(lastSeen)}
                      </span>
                    </div>
                  </div>
                  <span style={{
                    fontFamily: "var(--font-mono-family)",
                    fontSize: "11px",
                    fontWeight: 500,
                    color: "var(--text-secondary)",
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius-pill)",
                    padding: "1px 7px",
                    flexShrink: 0,
                  }}>
                    ×{count}
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>
    </aside>
  );
}

function ChevronRightIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}
function FilterIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
    </svg>
  );
}
