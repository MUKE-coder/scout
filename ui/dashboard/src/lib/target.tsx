// A single, app-wide "which target am I looking at" selection. The top bar shows
// it on every page, and the single-target pages (Overview, Stack) follow it, so
// it is always clear whether the dashboard is showing a given repo or site.
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useApi } from "./useApi";
import type { Overview } from "./types";

export interface TargetInfo {
  name: string;
  kind: "repo" | "url";
  detail: string; // the repo path or the site URL, for display
}

interface TargetCtx {
  targets: TargetInfo[];
  current: TargetInfo | null;
  setCurrent: (name: string) => void;
}

const Ctx = createContext<TargetCtx | null>(null);
const STORAGE_KEY = "scout.target";

export function TargetProvider({ children }: { children: ReactNode }) {
  const { data } = useApi<Overview>("/overview");
  const [selected, setSelected] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });

  const targets = useMemo<TargetInfo[]>(
    () =>
      (data?.targets ?? []).map((t) => ({
        name: t.target.name,
        kind: t.target.repo ? "repo" : "url",
        detail: t.target.repo || t.target.url || t.target.name,
      })),
    [data],
  );

  const current = targets.find((t) => t.name === selected) ?? targets[0] ?? null;

  const setCurrent = (name: string) => {
    setSelected(name);
    try {
      localStorage.setItem(STORAGE_KEY, name);
    } catch {
      /* ignore: storage may be unavailable */
    }
  };

  // Keep the stored selection valid if targets change (e.g. one is removed).
  useEffect(() => {
    if (selected && targets.length > 0 && !targets.some((t) => t.name === selected)) {
      setCurrent(targets[0].name);
    }
  }, [targets, selected]);

  return <Ctx.Provider value={{ targets, current, setCurrent }}>{children}</Ctx.Provider>;
}

export function useTarget(): TargetCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTarget must be used within a TargetProvider");
  return ctx;
}
