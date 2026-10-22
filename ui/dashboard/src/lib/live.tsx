import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, getToken } from "./api";
import type { ScanProgress } from "./types";

interface LiveEvent {
  type: "scan.started" | "check.finished" | "finding" | "scan.finished";
  scan_id: string;
  check_id?: string;
  count?: number;
  error?: string;
  total?: number;
  done?: number;
  time: string;
}

interface LiveState {
  scans: ScanProgress[];
  connected: boolean;
  killed: boolean;
  refresh: () => void;
}

const LiveContext = createContext<LiveState>({ scans: [], connected: false, killed: false, refresh: () => {} });

export const useLive = () => useContext(LiveContext);

// LiveProvider keeps one WebSocket to /scout/ws/live for the whole app,
// applies events to a snapshot from /scans/running, and reconnects with
// backoff. Missed events are repaired by refetching the snapshot.
export function LiveProvider({ children }: { children: ReactNode }) {
  const [scans, setScans] = useState<ScanProgress[]>([]);
  const [connected, setConnected] = useState(false);
  const [killed, setKilled] = useState(false);
  const retry = useRef(0);

  const refresh = useCallback(() => {
    api<{ killed: boolean; running: ScanProgress[] }>("/status")
      .then((s) => {
        setScans(s.running ?? []);
        setKilled(s.killed);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      const token = getToken();
      if (!token || closed) return;
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/scout/ws/live?token=${encodeURIComponent(token)}`);
      ws.onopen = () => {
        retry.current = 0;
        setConnected(true);
        refresh();
      };
      ws.onmessage = (msg) => {
        try {
          apply(JSON.parse(msg.data) as LiveEvent);
        } catch {
          /* ignore malformed */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (closed) return;
        const delay = Math.min(30000, 1000 * 2 ** retry.current++);
        timer = setTimeout(connect, delay);
      };
    };

    const apply = (ev: LiveEvent) => {
      if (ev.type === "finding") return;
      setScans((prev) => {
        const list = [...prev];
        let i = list.findIndex((s) => s.id === ev.scan_id);
        if (i < 0) {
          if (ev.type !== "scan.started") return prev;
          list.unshift({ id: ev.scan_id, started: ev.time, total: ev.total ?? 0, done: 0, findings: 0, checks: [], finished: false });
          i = 0;
        }
        const s = { ...list[i], checks: [...(list[i].checks ?? [])] };
        if (ev.type === "check.finished") {
          s.done = ev.done ?? s.done + 1;
          s.findings += ev.count ?? 0;
          s.checks.push({ id: ev.check_id ?? "", findings: ev.count ?? 0, error: ev.error });
        } else if (ev.type === "scan.finished") {
          s.finished = true;
          s.done = s.total;
        }
        list[i] = s;
        return list;
      });
    };

    refresh();
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [refresh]);

  return <LiveContext.Provider value={{ scans, connected, killed, refresh }}>{children}</LiveContext.Provider>;
}
