import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router";
import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import { Login } from "./pages/Login";
import { useAuthed } from "./lib/auth";

// Pages load on demand so charting code is only fetched where it is used.
const Overview = lazy(() => import("./pages/Overview").then((m) => ({ default: m.Overview })));
const Findings = lazy(() => import("./pages/Findings").then((m) => ({ default: m.Findings })));
const Live = lazy(() => import("./pages/Live").then((m) => ({ default: m.Live })));
const Settings = lazy(() => import("./pages/Settings").then((m) => ({ default: m.Settings })));
const History = lazy(() => import("./pages/History").then((m) => ({ default: m.History })));
const Surface = lazy(() => import("./pages/Surface").then((m) => ({ default: m.Surface })));
const Stack = lazy(() => import("./pages/Stack").then((m) => ({ default: m.Stack })));
const Compliance = lazy(() => import("./pages/Compliance").then((m) => ({ default: m.Compliance })));

export function App() {
  const authed = useAuthed();
  if (!authed) return <Login />;
  return (
    <Suspense fallback={<Spinner />}>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Overview />} />
          <Route path="findings" element={<Findings />} />
          <Route path="live" element={<Live />} />
          <Route path="surface" element={<Surface />} />
          <Route path="stack" element={<Stack />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="history" element={<History />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
