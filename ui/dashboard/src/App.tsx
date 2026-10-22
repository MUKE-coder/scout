import { Navigate, Route, Routes } from "react-router";
import { Shell } from "./components/Shell";
import { Placeholder } from "./pages/Placeholder";

export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Placeholder title="Overview" />} />
        <Route path="findings" element={<Placeholder title="Findings" />} />
        <Route path="live" element={<Placeholder title="Live scan" />} />
        <Route path="settings" element={<Placeholder title="Settings" />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
