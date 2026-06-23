export interface SeverityStyle {
  fg: string;
  bg: string;
  badgeFg: string; // letter badge text (uw-yellow-01 for LOW/benign)
  letter: string;  // C / M / L / ?
  label: string;
  rank: number;
}

const STYLES: Record<string, SeverityStyle> = {
  HIGH: {
    fg: "var(--severity-critical)",
    bg: "var(--severity-critical-bg)",
    badgeFg: "var(--severity-critical)",
    letter: "C",
    label: "malicious",
    rank: 3,
  },
  GRAY: {
    fg: "var(--severity-medium)",
    bg: "var(--severity-medium-bg)",
    badgeFg: "var(--severity-medium)",
    letter: "M",
    label: "suspicious",
    rank: 2,
  },
  LOW: {
    fg: "var(--severity-low)",
    bg: "var(--severity-low-bg)",
    badgeFg: "var(--uw-yellow-01)",
    letter: "L",
    label: "benign",
    rank: 1,
  },
};

const FALLBACK: SeverityStyle = {
  fg: "var(--severity-info)",
  bg: "var(--severity-info-bg)",
  badgeFg: "var(--severity-info)",
  letter: "?",
  label: "unknown",
  rank: 0,
};

export function severity(band: string | undefined): SeverityStyle {
  return STYLES[(band || "").toUpperCase()] ?? FALLBACK;
}

export function severityRank(band: string | undefined): number {
  return severity(band).rank;
}
