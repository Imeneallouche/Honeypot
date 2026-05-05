import { useCallback, useEffect, useRef, useState } from "react";

import { useAuthStore } from "../../store/authStore";

const MAX_EVENTS = 100;

export function useLiveFeed() {
  const token = useAuthStore((s) => s.accessToken);
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [isConnected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const delayRef = useRef(1000);
  const timerRef = useRef<number>();

  const append = useCallback((raw: unknown) => {
    if (typeof raw !== "object" || raw === null) return;
    const row = raw as Record<string, unknown>;
    if (row.type === "ping") return;
    setEvents((prev) => [row, ...prev].slice(0, MAX_EVENTS));
  }, []);

  useEffect(() => {
    if (!token) {
      setConnected(false);
      return;
    }

    let cancelled = false;

    const connect = () => {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const url = `${proto}//${window.location.host}/ws/live-feed?token=${encodeURIComponent(token)}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        delayRef.current = 1000;
        setConnected(true);
      };

      ws.onmessage = (ev) => {
        try {
          append(JSON.parse(ev.data as string));
        } catch {
          /* ignore */
        }
      };

      ws.onerror = () => {
        setConnected(false);
      };

      ws.onclose = () => {
        setConnected(false);
        if (cancelled) return;
        const wait = Math.min(30_000, delayRef.current);
        timerRef.current = window.setTimeout(() => {
          delayRef.current = Math.min(30_000, Math.floor(delayRef.current * 1.5));
          connect();
        }, wait);
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (timerRef.current) window.clearTimeout(timerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [token, append]);

  return { events, isConnected };
}
