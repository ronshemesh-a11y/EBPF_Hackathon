import type { FeedItem } from "../lib/types";
import { fmtTime } from "../lib/format";

export function MaliciousToast({
  item,
  onInvestigate,
  onDismiss,
}: {
  item: FeedItem;
  onInvestigate: () => void;
  onDismiss: () => void;
}) {
  return (
    <div style={{
      position: "fixed",
      top: "68px",
      right: "24px",
      width: "368px",
      zIndex: 60,
    }}>
      <div
        onClick={onInvestigate}
        className="uw-toast-slide"
        style={{
          background: "var(--surface-card)",
          border: "1px solid var(--uw-critical-line)",
          borderRadius: "8px",
          boxShadow: "0 10px 15px -3px rgba(0,0,0,0.14)",
          padding: "14px",
          display: "flex",
          gap: "12px",
          cursor: "pointer",
        }}
      >
        {/* Alert icon chip */}
        <div style={{
          width: "34px",
          height: "34px",
          flexShrink: 0,
          borderRadius: "8px",
          background: "var(--severity-critical-bg)",
          color: "var(--severity-critical)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}>
          <AlertTriangleIcon />
        </div>

        {/* Content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "13px", fontWeight: 500, color: "var(--severity-critical)" }}>
              Malicious command detected
            </span>
            <span style={{ fontFamily: "var(--font-mono-family)", fontSize: "10px", color: "var(--text-tertiary)" }}>
              {fmtTime(item.ts)}
            </span>
          </div>
          <div style={{
            fontFamily: "var(--font-mono-family)",
            fontSize: "12px",
            color: "var(--text-primary)",
            marginTop: "5px",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}>
            {item.command}
          </div>
          <div style={{ fontSize: "12px", fontWeight: 500, color: "var(--action-primary)", marginTop: "8px" }}>
            Investigate →
          </div>
        </div>

        {/* Dismiss button */}
        <button
          onClick={(e) => { e.stopPropagation(); onDismiss(); }}
          className="uw-icon-btn"
          title="Dismiss"
          style={{
            width: "24px",
            height: "24px",
            flexShrink: 0,
            border: "none",
            background: "transparent",
            borderRadius: "6px",
            color: "var(--text-tertiary)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            alignSelf: "flex-start",
          }}
        >
          <CloseIcon />
        </button>
      </div>
    </div>
  );
}

function AlertTriangleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
function CloseIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
