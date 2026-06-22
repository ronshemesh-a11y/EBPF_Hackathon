import { Info } from "lucide-react";
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

export function DetailPanel({ selected }: { selected: FeedItem | null }) {
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
              {Math.round(selected.risk_score * 100)}%
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
            </Field>
          )}

          {selected.risk_indicators && selected.risk_indicators.length > 0 && (
            <Field label="Risk indicators">
              <div className="flex flex-wrap gap-4">
                {selected.risk_indicators.map((ind) => (
                  <span
                    key={ind}
                    className="rounded-4 px-4 font-mono"
                    style={{
                      fontSize: "12px",
                      background: "var(--bg-secondary)",
                      color: "var(--text-secondary)",
                      border: "1px solid var(--border-subtle)",
                    }}
                  >
                    {ind}
                  </span>
                ))}
              </div>
            </Field>
          )}

          <Field label="Metadata">
            <div className="grid" style={{ gridTemplateColumns: "auto 1fr", gap: "4px 12px", fontSize: "12px" }}>
              <Meta k="executable" v={selected.executable || "—"} />
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
