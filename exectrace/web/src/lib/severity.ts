// Band → Upwind severity tokens. Colors come ONLY from CSS variables defined
// in the Upwind design system — never hardcoded hex. The brief's mapping:
//   HIGH  (malicious)            → --severity-critical / -bg
//   GRAY  (suspicious)           → --severity-medium   / -bg
//   LOW   (benign)               → --severity-info     / -bg
//   unknown / error / anything   → --severity-info     / -bg
export interface SeverityStyle {
  fg: string; // CSS var() for text/icon/border accent
  bg: string; // CSS var() for the tinted background
  label: string; // sentence-case label
  rank: number; // sort weight, higher = more severe
}

const STYLES: Record<string, SeverityStyle> = {
  HIGH: { fg: "var(--severity-critical)", bg: "var(--severity-critical-bg)", label: "High", rank: 3 },
  GRAY: { fg: "var(--severity-medium)", bg: "var(--severity-medium-bg)", label: "Gray", rank: 2 },
  LOW: { fg: "var(--severity-info)", bg: "var(--severity-info-bg)", label: "Low", rank: 1 },
};

const FALLBACK: SeverityStyle = {
  fg: "var(--severity-info)",
  bg: "var(--severity-info-bg)",
  label: "Unknown",
  rank: 0,
};

export function severity(band: string | undefined): SeverityStyle {
  return STYLES[(band || "").toUpperCase()] ?? FALLBACK;
}

// severityRank for sorting alerts (HIGH → GRAY → LOW → unknown).
export function severityRank(band: string | undefined): number {
  return severity(band).rank;
}
