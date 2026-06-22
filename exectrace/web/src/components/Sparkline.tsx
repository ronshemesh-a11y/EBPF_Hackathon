// Sparkline: a minimal inline-SVG line of recent values (no chart library). Used
// for the events/sec history in the header — a visual "it's racing".
export function Sparkline({
  values,
  width = 84,
  height = 24,
  color = "var(--action-primary)",
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (values.length < 2) {
    return <svg width={width} height={height} aria-hidden />;
  }
  const max = Math.max(1, ...values);
  const n = values.length;
  const step = width / (n - 1);
  const y = (v: number) => height - (v / max) * (height - 2) - 1;

  const line = values.map((v, i) => `${i * step},${y(v)}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;

  return (
    <svg width={width} height={height} aria-hidden style={{ display: "block" }}>
      <polygon points={area} fill={color} opacity={0.12} />
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
