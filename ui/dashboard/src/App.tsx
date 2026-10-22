import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router";
import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import { Placeholder } from "./pages/Placeholder";
import { Login } from "./pages/Login";
import { useAuthed } from "./lib/auth";

// Pages load on demand so charting code is only fetched where it is used.
const Overview = lazy(() => import("./pages/Overview").then((m) => ({ default: m.Overview })));

export function App() {
  const authed = useAuthed();
  if (!authed) return <Login />;
  return (
    <Suspense fallback={<Spinner />}>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Overview />} />
          <Route path="findings" element={<Placeholder title="Findings" />} />
          <Route path="live" element={<Placeholder title="Live scan" />} />
          <Route path="settings" element={<Placeholder title="Settings" />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
