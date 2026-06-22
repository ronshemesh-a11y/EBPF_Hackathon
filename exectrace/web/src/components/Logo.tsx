import { Radar } from "lucide-react";

// Logo renders the Upwind brand mark in the header.
//
// TODO: drop in upwind-logo.svg
//   Export from Upwind Design System → Brand → Logo as a TRANSPARENT-background
//   SVG (the design-system illustrations bake in a white backdrop; grab the
//   transparent version so it sits on the dark --surface-card header), and save
//   it to web/src/assets/upwind-logo.svg. It is then picked up automatically by
//   the glob below — no code change needed.
//
// Until the asset exists we fall back to the Radar icon so the build never
// breaks on a missing import.
const logoModules = import.meta.glob<{ default: string }>("../assets/upwind-logo.svg", {
  eager: true,
});
const logoSrc = Object.values(logoModules)[0]?.default;

export function Logo({ size = 22 }: { size?: number }) {
  if (logoSrc) {
    return <img src={logoSrc} alt="Upwind" style={{ height: size, width: "auto" }} />;
  }
  // Fallback: Radar icon in brand blue until the SVG is dropped in.
  return <Radar size={size - 4} style={{ color: "var(--action-primary)" }} />;
}
