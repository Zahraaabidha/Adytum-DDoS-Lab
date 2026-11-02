import { Route, Routes } from "react-router-dom";
import { Overview } from "../pages/Overview";
import { ThreatFeed } from "../pages/ThreatFeed";
import { SandboxLab } from "../pages/SandboxLab";
import { Analytics } from "../pages/Analytics";
import { Alerts } from "../pages/Alerts";
import { AlertDetail } from "../pages/AlertDetail";
import { Settings } from "../pages/Settings";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Overview />} />
      <Route path="/threat-intel" element={<ThreatFeed />} />
      <Route path="/sandbox" element={<SandboxLab />} />
      <Route path="/analytics" element={<Analytics />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/alerts/:id" element={<AlertDetail />} />
      <Route path="/settings" element={<Settings />} />
    </Routes>
  );
}
