import { useEffect, useRef } from "react";
import type { FeedItem } from "../lib/types";
import { severity } from "../lib/severity";
import { fmtTime } from "../lib/format";
import { SourceChip } from "./SourceChip";

// LiveFeed: every verdict scrolling in, newest on top, color-banded. Commands
// in DM Mono. Dense rows, Upwind console style.
export function LiveFeed({
  items,
  selectedId,
  onSelect,
}: {
  items: FeedItem[];
  selectedId: string | null;
  onSelect: (it: FeedItem) => void;
}) {
  // Track the newest seq to apply the flash class only to genuinely new rows.
  const lastSeq = useRef(0);
  useEffect(() => {
    if (items.length) lastSeq.current = items[0]._seq;
  }, [items]);

  return (
    <Panel title="Live feed" count={items.length}>
      <div className="overflow-y-auto" style={{ flex: 1 }}>
        {items.length === 0 && <Empty>Waiting for live events…</Empty>}
        {items.map((it) => {
          const s = severity(it.band);
          const selected = it._id === selectedId;
          // Newest live arrival pops + flashes once (history rows never animate).
          const isNewLive = it._live && it._seq === lastSeq.current;
          return (
            <button
              key={it._id}
              onClick={() => onSelect(it)}
              className={`flex w-full items-center gap-8 px-12 text-left ${
                isNewLive ? "uw-flash uw-pop" : ""
              }`}
              style={{
                height: "30px",
                borderBottom: "1px solid var(--border-subtle)",
                borderLeft: `2px solid ${s.fg}`,
                background: selected ? "var(--interactive-hover)" : "transparent",
              }}
            >
              <span
                className="font-mono shrink-0"
                style={{ color: "var(--text-tertiary)", fontSize: "11px", width: "84px" }}
              >
                {fmtTime(it.ts)}
              </span>
              <span
                className="font-mono truncate"
                style={{ color: "var(--text-primary)", fontSize: "12px", flex: 1 }}
              >
                {it.command}
              </span>
              <SourceChip source={it.source} latencyMs={it.latency_ms} compact />
              <span
                className="shrink-0 rounded-4 px-4 font-mono"
                style={{ color: s.fg, background: s.bg, fontSize: "10px", fontWeight: 500 }}
              >
                {it.score.toFixed(2)}
              </span>
            </button>
          );
        })}
      </div>
    </Panel>
  );
}

// --- shared panel chrome (used by feed + alerts + detail) ---

export function Panel({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section
      className="flex flex-col overflow-hidden rounded-8"
      style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-subtle)",
        boxShadow: "var(--shadow-card)",
        minHeight: 0,
      }}
    >
      <header
        className="flex items-center justify-between px-12 shrink-0"
        style={{ height: "36px", borderBottom: "1px solid var(--border-subtle)" }}
      >
        <span className="uw-h4" style={{ fontSize: "13px" }}>
          {title}
        </span>
        {count !== undefined && (
          <span className="font-mono uw-body-sm" style={{ color: "var(--text-tertiary)" }}>
            {count}
          </span>
        )}
      </header>
      {children}
    </section>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-12 py-24 uw-body-sm" style={{ color: "var(--text-tertiary)" }}>
      {children}
    </div>
  );
}
