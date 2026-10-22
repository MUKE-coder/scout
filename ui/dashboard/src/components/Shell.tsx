import { NavLink, Outlet } from "react-router";
import { Activity, LayoutDashboard, ListChecks, LogOut, Moon, Settings, Sun } from "lucide-react";
import { useTheme } from "../lib/theme";
import { setToken } from "../lib/api";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/live", label: "Live scan", icon: Activity },
  { to: "/settings", label: "Settings", icon: Settings },
];

// App shell: 240px sidebar, 56px top bar, one scrollable main area.
export function Shell() {
  const [theme, toggleTheme] = useTheme();
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
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-border px-4 md:px-8">
          <span className="text-[13px] font-medium text-muted md:hidden">Scout</span>
          <span className="hidden md:block" />
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
