import { useMemo } from "react";
import type { FeedItem } from "../lib/types";
import { severity, severityRank } from "../lib/severity";
import { SeverityBadge, MitreTags } from "./Badge";
import { Panel, Empty } from "./LiveFeed";

// AlertList: flagged verdicts (not LOW) sorted by severity (HIGH → GRAY), then
// newest first within a band. Each row shows command, verdict, confidence,
// reason, MITRE — the analyst's triage list.
export function AlertList({
  items,
  selectedId,
  onSelect,
}: {
  items: FeedItem[];
  selectedId: string | null;
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
    <Panel title="Alerts & incidents" count={alerts.length}>
      <div className="overflow-y-auto" style={{ flex: 1 }}>
        {alerts.length === 0 && <Empty>no flagged activity yet</Empty>}
        {alerts.map((it) => {
          const s = severity(it.band);
          const selected = it._id === selectedId;
          return (
            <button
              key={it._id}
              onClick={() => onSelect(it)}
              className="block w-full px-12 py-8 text-left"
              style={{
                borderBottom: "1px solid var(--border-subtle)",
                borderLeft: `3px solid ${s.fg}`,
                background: selected ? "var(--interactive-hover)" : "transparent",
              }}
            >
              <div className="flex items-center gap-8">
                <SeverityBadge band={it.band} />
                <span style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
                  {it.verdict || "unknown"}
                </span>
                <span
                  className="ml-auto font-mono"
                  style={{ color: s.fg, fontSize: "12px", fontWeight: 500 }}
                >
                  {Math.round(it.risk_score * 100)}%
                </span>
              </div>
              <div
                className="font-mono truncate"
                style={{ color: "var(--text-primary)", fontSize: "12px", marginTop: "4px" }}
              >
                {it.command}
              </div>
              {it.reason && (
                <div
                  className="truncate"
                  style={{ color: "var(--text-secondary)", fontSize: "12px", marginTop: "2px" }}
                >
                  {it.reason}
                </div>
              )}
              {it.mitre && it.mitre.length > 0 && (
                <div style={{ marginTop: "6px" }}>
                  <MitreTags mitre={it.mitre} />
                </div>
              )}
            </button>
          );
        })}
      </div>
    </Panel>
  );
}
