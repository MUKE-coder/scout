import { Link, NavLink, Outlet } from "react-router";
import { LiveProvider, useLive } from "../lib/live";
import { Activity, Boxes, History, LayoutDashboard, ListChecks, LogOut, Moon, Network, Settings as SettingsIcon, ShieldCheck, Sun } from "lucide-react";
import { useTheme } from "../lib/theme";
import { setToken } from "../lib/api";
import { useApi } from "../lib/useApi";
import type { Settings } from "../lib/types";
import { NewScanButton } from "./NewScanButton";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/surface", label: "Attack surface", icon: Network },
  { to: "/stack", label: "Stack & deps", icon: Boxes },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/live", label: "Live scan", icon: Activity },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

// Top-bar pill shown while a scan is live; links to the Live page.
function ScanStatusPill() {
  const { scans, killed } = useLive();
  const running = scans.filter((s) => !s.finished);
  if (killed) {
    return (
      <Link to="/live" className="inline-flex h-[22px] items-center rounded-md bg-critical/12 px-2 text-[12px] font-medium text-critical-fg">
        Kill switch on
      </Link>
    );
  }
  if (running.length === 0) return null;
  const s = running[0];
  return (
    <Link to="/live" className="inline-flex h-[22px] items-center gap-2 rounded-md bg-accent-subtle px-2 text-[12px] font-medium text-text">
      <span className="size-1.5 animate-pulse rounded-full bg-accent" aria-hidden />
      Scanning <span className="tabular">{s.done}/{s.total}</span>
    </Link>
  );
}

// App shell: 240px sidebar, 56px top bar, one scrollable main area.
export function Shell() {
  return (
    <LiveProvider>
      <ShellLayout />
    </LiveProvider>
  );
}

function ShellLayout() {
  const [theme, toggleTheme] = useTheme();
  const settings = useApi<Settings>("/settings");
  return (
    <div className="flex h-screen bg-bg text-text">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-border md:flex">
        <div className="flex h-14 items-center px-6 text-[16px] font-semibold tracking-tight">Scout</div>
        <nav className="flex flex-1 flex-col gap-1 px-3 py-2">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                [
                  "relative flex h-9 items-center gap-3 rounded-lg px-3 text-[13px] font-medium transition-colors duration-150",
                  isActive
                    ? "bg-accent-subtle text-text before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-full before:bg-accent"
                    : "text-muted hover:bg-surface-2 hover:text-text",
                ].join(" ")
              }
            >
              <Icon size={20} strokeWidth={1.5} aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="flex flex-col gap-1 border-t border-border p-3">
          <button
            type="button"
            onClick={() => setToken(null)}
            className="flex h-9 w-full items-center gap-3 rounded-lg px-3 text-[13px] font-medium text-muted transition-colors duration-150 hover:bg-surface-2 hover:text-text"
          >
            <LogOut size={16} strokeWidth={1.5} aria-hidden />
            Sign out
          </button>
          <button
            type="button"
            onClick={toggleTheme}
            className="flex h-9 w-full items-center gap-3 rounded-lg px-3 text-[13px] font-medium text-muted transition-colors duration-150 hover:bg-surface-2 hover:text-text"
          >
            {theme === "dark" ? <Sun size={16} strokeWidth={1.5} aria-hidden /> : <Moon size={16} strokeWidth={1.5} aria-hidden />}
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border px-4 md:px-8">
          <span className="text-[13px] font-medium text-muted">
            <span className="md:hidden">Scout · </span>
            {settings.data?.app_name}
            {settings.data && <span className="text-subtle"> · {settings.data.environment}</span>}
          </span>
          <div className="flex items-center gap-3">
            <ScanStatusPill />
            <NewScanButton targets={settings.data?.targets ?? []} />
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1280px] px-4 py-8 md:px-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
