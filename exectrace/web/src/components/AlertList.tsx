import { useMemo } from "react";
import type { FeedItem } from "../lib/types";
import { severity, severityRank } from "../lib/severity";
import { fmtTime } from "../lib/format";

export function AlertList({
  items,
  onSelect,
}: {
  items: FeedItem[];
  onSelect: (it: FeedItem) => void;
}) {
  const alerts = useMemo(() => {
    return items
      .filter((it) => (it.band || "").toUpperCase() !== "LOW")
      .sort((a, b) => {
        const r = severityRank(b.band) - severityRank(a.band);
        return r !== 0 ? r : b._seq - a._seq;
      });
  }, [items]);

  return (
    <div style={{
      background: "var(--surface-card)",
      border: "1px solid var(--border-subtle)",
      borderRadius: "8px",
      boxShadow: "var(--shadow-sm)",
      marginBottom: "16px",
    }}>
      {/* Card header */}
      <div style={{
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        padding: "14px 16px",
        borderBottom: "1px solid var(--border-subtle)",
      }}>
        <div>
          <div style={{ fontSize: "14px", fontWeight: 500, color: "var(--text-primary)" }}>
            Alerts &amp; incidents
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Flagged executions · most recent first · full command line
          </div>
        </div>
        <button style={{
          fontSize: "13px",
          fontWeight: 500,
          color: "var(--action-primary)",
          background: "transparent",
          border: "none",
          cursor: "pointer",
        }}>
          View all
        </button>
      </div>

      {/* Rows */}
      <div style={{ padding: "4px 16px 8px" }}>
        {alerts.length === 0 ? (
          <div style={{ padding: "16px 0", fontSize: "13px", color: "var(--text-tertiary)" }}>
            waiting for live events…
          </div>
        ) : (
          alerts.map((it, idx) => {
            const s = severity(it.band);
            const isLast = idx === alerts.length - 1;
            return (
              <button
                key={it._id}
                onClick={() => onSelect(it)}
                className="uw-alert-row"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  padding: "11px 0",
                  borderBottom: isLast ? "none" : "1px solid var(--bg-tertiary)",
                  background: "transparent",
                  border: "none",
                  borderBottomWidth: isLast ? "0" : "1px",
                  borderBottomStyle: "solid",
                  borderBottomColor: isLast ? "transparent" : "var(--bg-tertiary)",
                  cursor: "pointer",
                  width: "100%",
                  textAlign: "left",
                }}
              >
                {/* Severity dot */}
                <span style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: s.fg,
                  flexShrink: 0,
                }} />
                {/* Command */}
                <span style={{
                  flex: 1,
                  minWidth: 0,
                  fontFamily: "var(--font-mono-family)",
                  fontSize: "13px",
                  color: "var(--text-primary)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}>
                  {it.command}
                </span>
                {/* Verdict pill */}
                <span style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "5px",
                  height: "20px",
                  padding: "0 8px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  fontWeight: 500,
                  lineHeight: 1,
                  color: s.fg,
                  background: s.bg,
                  flexShrink: 0,
                }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: s.fg }} />
                  {it.verdict || "unknown"}
                </span>
                {/* Time */}
                <span style={{
                  fontFamily: "var(--font-mono-family)",
                  fontSize: "11px",
                  color: "var(--text-tertiary)",
                  flexShrink: 0,
                  width: "62px",
                  textAlign: "right",
                }}>
                  {fmtTime(it.ts).slice(0, 8)}
                </span>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
