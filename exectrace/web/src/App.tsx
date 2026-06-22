import { useEffect, useState } from "react";
import { Circle } from "lucide-react";
import { useVerdicts } from "./lib/useVerdicts";
import type { FeedItem } from "./lib/types";
import { Logo } from "./components/Logo";
import { MetricBar } from "./components/MetricBar";
import { LiveFeed } from "./components/LiveFeed";
import { AlertList } from "./components/AlertList";
import { DetailPanel } from "./components/DetailPanel";

export default function App() {
  const { items, metrics } = useVerdicts();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Auto-select the first alert once one exists and nothing is selected yet, so
  // the detail panel isn't empty on first flagged activity.
  useEffect(() => {
    if (selectedId) return;
    const firstAlert = items.find((it) => (it.band || "").toUpperCase() !== "LOW");
    if (firstAlert) setSelectedId(firstAlert._id);
  }, [items, selectedId]);

  const selected = items.find((it) => it._id === selectedId) ?? null;
  const select = (it: FeedItem) => setSelectedId(it._id);

  return (
    <div className="flex flex-col" style={{ height: "100%", background: "var(--bg-primary)" }}>
      {/* Top header — 56px Upwind header height */}
      <header
        className="flex items-center gap-16 px-16 shrink-0"
        style={{
          height: "var(--upwind-header-height)",
          borderBottom: "1px solid var(--border-subtle)",
          background: "var(--surface-card)",
        }}
      >
        <div className="flex items-center gap-8">
          <Logo size={22} />
          <span className="uw-h4" style={{ fontSize: "15px" }}>
            exectrace
          </span>
          <span className="uw-body-sm" style={{ color: "var(--text-tertiary)" }}>
            · SOC console
          </span>
        </div>
        <div className="ml-auto">
          <MetricBar m={metrics} />
        </div>
        <ConnDot connected={metrics.connected} />
      </header>

      {/* Body: optional sidebar + 3-pane grid */}
      <div className="flex" style={{ flex: 1, minHeight: 0 }}>
        <Sidebar />
        <main
          className="grid gap-12 p-12"
          style={{
            flex: 1,
            minHeight: 0,
            gridTemplateColumns: "minmax(280px, 1fr) minmax(340px, 1.3fr) minmax(320px, 1fr)",
          }}
        >
          <LiveFeed items={items} selectedId={selectedId} onSelect={select} />
          <AlertList items={items} selectedId={selectedId} onSelect={select} />
          <DetailPanel selected={selected} items={items} />
        </main>
      </div>
    </div>
  );
}

function ConnDot({ connected }: { connected: boolean }) {
  return (
    <span
      className="flex items-center gap-4 uw-body-sm"
      style={{ color: connected ? "var(--severity-safe)" : "var(--severity-info)" }}
      title={connected ? "live" : "disconnected"}
    >
      <Circle size={9} fill="currentColor" />
      {connected ? "live" : "offline"}
    </span>
  );
}

// Sidebar — 224px Upwind sidebar width. Single section for now; campaign /
// kill-chain views land here if Tier-2 ships.
function Sidebar() {
  return (
    <nav
      className="flex flex-col gap-4 p-12 shrink-0"
      style={{
        width: "var(--upwind-sidebar-width)",
        borderRight: "1px solid var(--border-subtle)",
        background: "var(--bg-secondary)",
      }}
    >
      <NavItem label="Live activity" active />
      <NavItem label="Incidents" />
      <NavItem label="Campaigns" muted />
    </nav>
  );
}

function NavItem({ label, active, muted }: { label: string; active?: boolean; muted?: boolean }) {
  return (
    <div
      className="rounded-4 px-12"
      style={{
        height: "32px",
        display: "flex",
        alignItems: "center",
        fontSize: "13px",
        fontWeight: active ? 500 : 400,
        color: muted ? "var(--text-tertiary)" : active ? "var(--text-primary)" : "var(--text-secondary)",
        background: active ? "var(--interactive-hover)" : "transparent",
      }}
    >
      {label}
      {muted && (
        <span className="ml-auto uw-body-xs" style={{ color: "var(--text-tertiary)" }}>
          soon
        </span>
      )}
    </div>
  );
}
