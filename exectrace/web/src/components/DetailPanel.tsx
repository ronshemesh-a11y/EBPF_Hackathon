import { useMemo } from "react";
import { ChevronRight, GitBranch, Info } from "lucide-react";
import type { FeedItem } from "../lib/types";
import { severity } from "../lib/severity";
import { SeverityBadge, MitreTags } from "./Badge";
import { Panel, Empty } from "./LiveFeed";
import { fmtTime } from "../lib/format";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "16px" }}>
      <div className="uw-label" style={{ marginBottom: "4px" }}>
        {label}
      </div>
      {children}
    </div>
  );
}

// buildLineage reconstructs the pid→ppid ancestor chain for the selected item
// from everything we've observed, ending at the selected process. Best-effort:
// ancestors only appear if their exec was also seen (eBPF emits ppid; the CSV
// replay does not, so the chain is just the process itself there).
function buildLineage(sel: FeedItem, items: FeedItem[]): FeedItem[] {
  const byPid = new Map<number, FeedItem>();
  // Prefer the most recent exec per pid.
  for (const it of items) {
    if (!byPid.has(it.pid)) byPid.set(it.pid, it);
  }
  const chain: FeedItem[] = [sel];
  const seen = new Set<number>([sel.pid]);
  let cur = sel;
  while (cur.ppid && cur.ppid !== 0 && !seen.has(cur.ppid)) {
    const parent = byPid.get(cur.ppid);
    if (!parent) break;
    chain.unshift(parent);
    seen.add(parent.pid);
    cur = parent;
  }
  return chain;
}

// procName extracts a short label for a lineage node (argv[0]-ish from command).
function procName(it: FeedItem): string {
  const first = (it.command || "").trim().split(/\s+/)[0] || "?";
  return first.split("/").pop() || first;
}

export function DetailPanel({
  selected,
  items,
}: {
  selected: FeedItem | null;
  items: FeedItem[];
}) {
  const lineage = useMemo(
    () => (selected ? buildLineage(selected, items) : []),
    [selected, items],
  );

  return (
    <Panel title="Detail">
      {!selected ? (
        <Empty>select an alert to inspect</Empty>
      ) : (
        <div className="overflow-y-auto px-16 py-16" style={{ flex: 1 }}>
          <div className="flex items-center gap-8" style={{ marginBottom: "16px" }}>
            <SeverityBadge band={selected.band} />
            <span style={{ color: "var(--text-secondary)", fontSize: "13px" }}>
              {selected.verdict || "unknown"}
            </span>
            <span
              className="ml-auto font-mono"
              style={{ color: severity(selected.band).fg, fontSize: "16px", fontWeight: 700 }}
            >
              {Math.round(selected.score * 100)}%
            </span>
          </div>

          <Field label="Command">
            <code
              className="uw-code block rounded-4 px-8 py-8"
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-subtle)",
                wordBreak: "break-all",
                fontSize: "12px",
              }}
            >
              {selected.command}
            </code>
          </Field>

          {selected.reason && (
            <Field label="Reason">
              <div className="flex gap-8" style={{ color: "var(--text-primary)", fontSize: "13px" }}>
                <Info size={15} style={{ color: "var(--text-tertiary)", flexShrink: 0, marginTop: "2px" }} />
                <span>{selected.reason}</span>
              </div>
            </Field>
          )}

          {selected.mitre && selected.mitre.length > 0 && (
            <Field label="MITRE ATT&CK">
              <MitreTags mitre={selected.mitre} />
              {selected.tactic && (
                <div style={{ color: "var(--text-secondary)", fontSize: "12px", marginTop: "6px" }}>
                  {selected.tactic}
                </div>
              )}
            </Field>
          )}

          <Field label="Process tree">
            <div className="flex flex-wrap items-center gap-4">
              <GitBranch size={15} style={{ color: "var(--text-tertiary)" }} />
              {lineage.map((node, i) => (
                <span key={node._id} className="flex items-center gap-4">
                  {i > 0 && <ChevronRight size={13} style={{ color: "var(--text-tertiary)" }} />}
                  <span
                    className="rounded-4 px-4 font-mono"
                    style={{
                      fontSize: "12px",
                      background:
                        node._id === selected._id ? severity(selected.band).bg : "var(--bg-secondary)",
                      color:
                        node._id === selected._id ? severity(selected.band).fg : "var(--text-secondary)",
                      border: "1px solid var(--border-subtle)",
                    }}
                    title={`pid ${node.pid}`}
                  >
                    {procName(node)}
                  </span>
                </span>
              ))}
            </div>
            {lineage.length === 1 && (
              <div style={{ color: "var(--text-tertiary)", fontSize: "11px", marginTop: "6px" }}>
                no parent lineage available for this event
              </div>
            )}
          </Field>

          <Field label="Metadata">
            <div className="grid" style={{ gridTemplateColumns: "auto 1fr", gap: "4px 12px", fontSize: "12px" }}>
              <Meta k="pid" v={String(selected.pid)} />
              {selected.ppid ? <Meta k="ppid" v={String(selected.ppid)} /> : null}
              <Meta k="source" v={selected.source || "—"} />
              <Meta k="time" v={fmtTime(selected.ts)} />
            </div>
          </Field>
        </div>
      )}
    </Panel>
  );
}

function Meta({ k, v }: { k: string; v: string }) {
  return (
    <>
      <span className="uw-label">{k}</span>
      <span className="font-mono" style={{ color: "var(--text-primary)" }}>
        {v}
      </span>
    </>
  );
}
