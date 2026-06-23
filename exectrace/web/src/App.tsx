import { useEffect, useRef, useState } from "react";
import { useVerdicts } from "./lib/useVerdicts";
import type { FeedItem } from "./lib/types";
import { TopBar } from "./components/TopBar";
import { IconRail } from "./components/IconRail";
import { MetricCards } from "./components/MetricCards";
import { AlertList } from "./components/AlertList";
import { SeveritySummary } from "./components/SeveritySummary";
import { RightDrawer } from "./components/RightDrawer";
import { MaliciousToast } from "./components/MaliciousToast";
import { DetailModal } from "./components/DetailModal";

export default function App() {
  const { items, aggregated, metrics, lastMalicious, clear } = useVerdicts();
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [toastItem, setToastItem] = useState<FeedItem | null>(null);
  const [detailItem, setDetailItem] = useState<FeedItem | null>(null);

  // Show toast whenever a new live malicious item arrives.
  // Track by _id so re-renders don't re-fire.
  const lastMaliciousId = useRef<string | null>(null);
  useEffect(() => {
    if (lastMalicious && lastMalicious._id !== lastMaliciousId.current) {
      lastMaliciousId.current = lastMalicious._id;
      setToastItem(lastMalicious);
    }
  }, [lastMalicious]);

  return (
    <div style={{
      position: "fixed",
      top: 0,
      right: 0,
      bottom: 0,
      left: 0,
      display: "flex",
      flexDirection: "column",
      background: "var(--bg-secondary)",
    }}>
      <TopBar metrics={metrics} />

      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <IconRail />

        {/* Center column: scrollable main */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <main style={{
            flex: 1,
            overflowY: "auto",
            padding: "24px",
            minHeight: 0,
          }}>
            {/* Page title row */}
            <div style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: "16px",
              marginBottom: "20px",
            }}>
              <div>
                <h1 style={{
                  margin: 0,
                  fontSize: "24px",
                  fontWeight: 500,
                  letterSpacing: "-0.01em",
                  color: "var(--text-primary)",
                }}>
                  Process executions
                </h1>
                <div style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" }}>
                  Runtime command analysis on{" "}
                  <span style={{ fontFamily: "var(--font-mono-family)" }}>ip-10-0-4-12</span>
                  {" "}· eBPF sensor active · classified by exectrace model
                </div>
                {/* Stat chips */}
                <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
                  <StatChip
                    icon={<ActivityChipIcon />}
                    label="events/sec"
                    value={metrics.eventsPerSec.toFixed(1)}
                    valueFg="var(--action-primary)"
                    iconStroke="var(--action-primary)"
                  />
                  <StatChip
                    icon={<ShieldChipIcon />}
                    label="flagged"
                    value={String(metrics.flagged)}
                    valueFg={metrics.flagged > 0 ? "var(--severity-medium)" : "var(--text-primary)"}
                    iconStroke={metrics.flagged > 0 ? "var(--severity-medium)" : "var(--text-secondary)"}
                  />
                </div>
              </div>
              <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
                {items.length > 0 && (
                  <button
                    onClick={() => { clear(); setToastItem(null); setDetailItem(null); }}
                    className="uw-btn-ghost"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      padding: "7px 12px",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "6px",
                      fontSize: "13px",
                      fontWeight: 500,
                      color: "var(--text-secondary)",
                      background: "var(--surface-card)",
                      cursor: "pointer",
                    }}
                  >
                    <ClearIcon />
                    Clear all
                  </button>
                )}
                <button
                  onClick={() => setDrawerOpen((o) => !o)}
                  className="uw-btn-ghost"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "7px 12px",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "6px",
                    fontSize: "13px",
                    fontWeight: 500,
                    color: "var(--text-primary)",
                    background: "var(--surface-card)",
                    cursor: "pointer",
                  }}
                >
                  <LiveFeedIcon />
                  Live feed
                </button>
              </div>
            </div>

            {/* Metric cards */}
            <MetricCards metrics={metrics} />

            {/* Alerts & incidents */}
            <AlertList items={items} onSelect={setDetailItem} />

            {/* Summary by severity */}
            <SeveritySummary metrics={metrics} />
          </main>

        </div>

        {/* Right collapsible live-feed drawer */}
        <RightDrawer
          open={drawerOpen}
          aggregated={aggregated}
          onToggle={() => setDrawerOpen((o) => !o)}
          onSelect={setDetailItem}
        />
      </div>

      {/* Reopen tab when drawer is closed */}
      {!drawerOpen && (
        <button
          onClick={() => setDrawerOpen(true)}
          style={{
            position: "fixed",
            top: "96px",
            right: 0,
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "10px",
            background: "var(--surface-card)",
            border: "1px solid var(--border-subtle)",
            borderRight: "none",
            borderRadius: "8px 0 0 8px",
            boxShadow: "-2px 2px 8px rgba(52,64,84,0.1)",
            color: "var(--action-primary)",
            fontSize: "12px",
            fontWeight: 500,
            cursor: "pointer",
            writingMode: "vertical-rl",
            zIndex: 20,
          }}
        >
          <LiveFeedIcon rotated />
          Live feed
        </button>
      )}

      {/* Malicious toast (top-right, malicious only) */}
      {toastItem && (
        <MaliciousToast
          item={toastItem}
          onInvestigate={() => { setDetailItem(toastItem); setToastItem(null); }}
          onDismiss={() => setToastItem(null)}
        />
      )}

      {/* Detail modal */}
      {detailItem && (
        <DetailModal item={detailItem} onClose={() => setDetailItem(null)} />
      )}
    </div>
  );
}

function StatChip({
  icon,
  label,
  value,
  valueFg,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  valueFg: string;
  iconStroke?: string;
}) {
  return (
    <div style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "8px",
      padding: "6px 12px",
      border: "1px solid var(--border-subtle)",
      borderRadius: "8px",
      background: "var(--surface-card)",
    }}>
      {icon}
      <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{label}</span>
      <span style={{
        fontSize: "14px",
        fontWeight: 700,
        fontFamily: "var(--font-mono-family)",
        color: valueFg,
      }}>
        {value}
      </span>
    </div>
  );
}

function ActivityChipIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--action-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

function ShieldChipIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--severity-medium)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function ClearIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14H6L5 6" />
      <path d="M10 11v6M14 11v6" />
      <path d="M9 6V4h6v2" />
    </svg>
  );
}

function LiveFeedIcon({ rotated }: { rotated?: boolean }) {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--action-primary)"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={rotated ? { transform: "rotate(90deg)" } : undefined}
    >
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <line x1="15" y1="3" x2="15" y2="21" />
    </svg>
  );
}
