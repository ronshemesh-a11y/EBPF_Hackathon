import { useEffect, useMemo, useRef, useState } from "react";
import type { AggregatedItem, FeedItem, Verdict } from "./types";

const MAX_ITEMS = 1000;

// Noise filter: show only the demo user's commands.
// Disabled until uid is included in the API response.
export const NOISE_FILTER_ENABLED = false;
export const DEMO_USER_UID = 1000;

// filterNoise returns true if the item should be shown.
// Currently a no-op; when uid lands in the API, compare it.uid === DEMO_USER_UID.
function filterNoise(v: Verdict): boolean {
  if (!NOISE_FILTER_ENABLED) return true;
  const cmd = (v.command || "").trim();
  // Kernel threads look like "[kworker/...]"
  return !cmd.startsWith("[");
}

export interface Metrics {
  total: number;
  flagged: number; // HIGH + GRAY
  flaggedPct: number; // 0..100
  perBand: { HIGH: number; GRAY: number; LOW: number };
  eventsPerSec: number;
  epsHistory: number[]; // ~last 60 per-second eps samples
  connected: boolean;
}

export interface VerdictsState {
  items: FeedItem[];          // newest first, raw
  aggregated: AggregatedItem[]; // de-duped by command text, newest first
  lastMalicious: FeedItem | null; // latest live HIGH-band item (toast trigger)
  metrics: Metrics;
  clear: () => void; // wipe all displayed events (stream keeps running)
}

let seq = 0;
function tag(v: Verdict, live: boolean): FeedItem {
  seq += 1;
  return { ...v, _id: `${v.pid}-${v.ts}-${seq}`, _seq: seq, _live: live };
}

function tsMillis(v: { ts: string }): number {
  const t = Date.parse(v.ts);
  return Number.isNaN(t) ? 0 : t;
}

export function useVerdicts(): VerdictsState {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [connected, setConnected] = useState(false);
  const [lastMalicious, setLastMalicious] = useState<FeedItem | null>(null);
  const arrivals = useRef<number[]>([]);
  const [eps, setEps] = useState(0);
  const [epsHistory, setEpsHistory] = useState<number[]>([]);
  const hwm = useRef(0);

  useEffect(() => {
    let alive = true;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;

    const record = (v: Verdict, isLive: boolean) => {
      if (!filterNoise(v)) return;
      if (isLive) arrivals.current.push(Date.now());
      const tagged = tag(v, isLive);
      if (isLive && (v.band || "").toUpperCase() === "HIGH") {
        setLastMalicious(tagged);
      }
      setItems((prev) => {
        const next = [tagged, ...prev];
        return next.length > MAX_ITEMS ? next.slice(0, MAX_ITEMS) : next;
      });
    };

    async function loadHistory() {
      try {
        const res = await fetch("/api/verdicts?limit=500");
        const rows: Verdict[] = await res.json();
        if (!alive) return;
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
          if (tsMillis(v) <= hwm.current) return;
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

    const tick = setInterval(() => {
      const now = Date.now();
      arrivals.current = arrivals.current.filter((t) => t >= now - 10_000);
      const rate = arrivals.current.length / 10;
      setEps(rate);
      const lastSec = arrivals.current.filter((t) => t >= now - 1_000).length;
      setEpsHistory((prev) => [...prev, lastSec].slice(-60));
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

  // Aggregate items by command text: items is newest-first, so the first
  // occurrence of each command key is its most recent execution.
  const aggregated = useMemo<AggregatedItem[]>(() => {
    const map = new Map<string, AggregatedItem>();
    for (const it of items) {
      const key = it.command;
      if (!map.has(key)) {
        map.set(key, {
          cmd: key,
          verdict: it.verdict,
          band: it.band,
          count: 1,
          lastSeen: it.ts,
          item: it,
        });
      } else {
        map.get(key)!.count++;
      }
    }
    return Array.from(map.values());
  }, [items]);

  const clear = () => {
    setItems([]);
    setLastMalicious(null);
    arrivals.current = [];
  };

  return {
    items,
    aggregated,
    lastMalicious,
    clear,
    metrics: {
      total,
      flagged,
      flaggedPct: total ? (flagged / total) * 100 : 0,
      perBand,
      eventsPerSec: eps,
      epsHistory,
      connected,
    },
  };
}
