import { useEffect, useRef, useState } from "react";
import type { FeedItem, Verdict } from "./types";

const MAX_ITEMS = 1000;

export interface Metrics {
  total: number;
  flagged: number; // not LOW
  flaggedPct: number; // 0..100
  perBand: { HIGH: number; GRAY: number; LOW: number };
  eventsPerSec: number; // rolling over the last ~10s window
  connected: boolean;
}

export interface VerdictsState {
  items: FeedItem[]; // newest first
  metrics: Metrics;
}

let seq = 0;
function tag(v: Verdict): FeedItem {
  seq += 1;
  return { ...v, _id: `${seq}-${v.ts}`, _seq: seq };
}

function tsMillis(v: { ts: string }): number {
  const t = Date.parse(v.ts);
  return Number.isNaN(t) ? 0 : t;
}

// useVerdicts loads history from /api/verdicts, then streams live verdicts over
// /ws (skipping the ws backlog that overlaps history). Returns newest-first
// items plus rolling metrics.
export function useVerdicts(): VerdictsState {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [connected, setConnected] = useState(false);
  // arrival timestamps (ms) for the events/sec rolling window
  const arrivals = useRef<number[]>([]);
  const [eps, setEps] = useState(0);

  // High-water mark: newest ts already shown from history, so the ws backlog
  // doesn't double-render it.
  const hwm = useRef(0);

  useEffect(() => {
    let alive = true;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;

    const record = (v: Verdict, isLive: boolean) => {
      if (isLive) arrivals.current.push(Date.now());
      setItems((prev) => {
        const head = prev[0];
        if (head && head.executable === v.executable && head.command === v.command) {
          // Same command as the newest row → bump its count (and refresh ts)
          // instead of flooding the feed with identical rows.
          const bumped = { ...head, _count: (head._count ?? 1) + 1, ts: v.ts };
          return [bumped, ...prev.slice(1)];
        }
        const next = [tag(v), ...prev];
        return next.length > MAX_ITEMS ? next.slice(0, MAX_ITEMS) : next;
      });
    };

    async function loadHistory() {
      try {
        const res = await fetch("/api/verdicts?limit=500");
        const rows: Verdict[] = await res.json();
        if (!alive) return;
        // API is newest-first; render oldest-first so newest ends on top.
        for (let i = rows.length - 1; i >= 0; i--) {
          record(rows[i], false);
          hwm.current = Math.max(hwm.current, tsMillis(rows[i]));
        }
      } catch {
        /* no history yet — live stream will fill in */
      }
    }

    function connect() {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => alive && setConnected(true);
      ws.onmessage = (e) => {
        if (!alive) return;
        try {
          const v: Verdict = JSON.parse(e.data);
          if (tsMillis(v) <= hwm.current) return; // already shown from history
          record(v, true);
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        if (!alive) return;
        setConnected(false);
        retry = setTimeout(connect, 1500);
      };
      ws.onerror = () => ws?.close();
    }

    loadHistory().then(() => alive && connect());

    // Recompute events/sec every second over a 10s sliding window.
    const tick = setInterval(() => {
      const cutoff = Date.now() - 10_000;
      arrivals.current = arrivals.current.filter((t) => t >= cutoff);
      setEps(arrivals.current.length / 10);
    }, 1000);

    return () => {
      alive = false;
      if (retry) clearTimeout(retry);
      clearInterval(tick);
      ws?.close();
    };
  }, []);

  const perBand = { HIGH: 0, GRAY: 0, LOW: 0 };
  for (const it of items) {
    const b = (it.band || "").toUpperCase();
    if (b === "HIGH" || b === "GRAY" || b === "LOW") perBand[b]++;
  }
  const total = items.length;
  const flagged = perBand.HIGH + perBand.GRAY;

  return {
    items,
    metrics: {
      total,
      flagged,
      flaggedPct: total ? (flagged / total) * 100 : 0,
      perBand,
      eventsPerSec: eps,
      connected,
    },
  };
}
