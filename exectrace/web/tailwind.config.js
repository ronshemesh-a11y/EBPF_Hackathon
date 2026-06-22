/**
 * Tailwind is pointed entirely at Upwind Design System CSS variables — no
 * default palette, no hardcoded hex. Every utility resolves to a token defined
 * in src/styles/upwind/. Drop the real styles.css in and the whole UI themes.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    // Replace (not extend) colors so stray default-palette utilities can't
    // introduce non-Upwind hex.
    colors: {
      transparent: "transparent",
      current: "currentColor",
      "bg-primary": "var(--bg-primary)",
      "bg-secondary": "var(--bg-secondary)",
      "surface-card": "var(--surface-card)",
      "text-primary": "var(--text-primary)",
      "text-secondary": "var(--text-secondary)",
      "text-tertiary": "var(--text-tertiary)",
      "text-link": "var(--text-link)",
      "border-subtle": "var(--border-subtle)",
      "border-primary": "var(--border-primary)",
      "action-primary": "var(--action-primary)",
      "action-primary-hover": "var(--action-primary-hover)",
      // Severity scale (band mapping lives in src/lib/severity.ts).
      "sev-critical": "var(--severity-critical)",
      "sev-critical-bg": "var(--severity-critical-bg)",
      "sev-medium": "var(--severity-medium)",
      "sev-medium-bg": "var(--severity-medium-bg)",
      "sev-info": "var(--severity-info)",
      "sev-info-bg": "var(--severity-info-bg)",
    },
    borderRadius: {
      none: "0",
      4: "var(--radius-4)",
      8: "var(--radius-8)",
      pill: "var(--radius-pill)",
    },
    spacing: {
      0: "0",
      4: "var(--space-4, 4px)",
      8: "var(--space-8)",
      12: "var(--space-12)",
      16: "var(--space-16)",
      24: "var(--space-24)",
      32: "var(--space-32)",
    },
    extend: {
      fontFamily: {
        sans: "var(--font-default-family)",
        mono: "var(--font-mono-family)",
      },
      boxShadow: {
        card: "var(--shadow-card)",
      },
      height: {
        header: "var(--upwind-header-height)",
      },
      width: {
        sidebar: "var(--upwind-sidebar-width)",
      },
    },
  },
  plugins: [],
};
