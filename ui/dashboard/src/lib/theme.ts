import { useCallback, useState } from "react";

export type Theme = "dark" | "light";

function current(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

// useTheme toggles data-theme on <html> and remembers the choice. Storage can
// be unavailable (private windows), so failures only lose the preference.
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(current);
  const toggle = useCallback(() => {
    const next: Theme = current() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("scout.theme", next);
    } catch {
      /* preference not persisted */
    }
    setTheme(next);
  }, []);
  return [theme, toggle];
}
