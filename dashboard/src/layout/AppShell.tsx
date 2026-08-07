import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { useThreatStream } from "../lib/ws";
import { useThreatStore } from "../store/threatStore";

interface AppShellProps {
  children: ReactNode;
}

/**
 * Single place the app-wide WS connection is wired -- pages read live
 * events from useThreatStore rather than each opening their own socket.
 */
export function AppShell({ children }: AppShellProps) {
  const pushEvent = useThreatStore((state) => state.pushEvent);
  const setConnectionStatus = useThreatStore((state) => state.setConnectionStatus);
  useThreatStream(pushEvent, setConnectionStatus);

  return (
    <div className="flex h-full min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">{children}</main>
    </div>
  );
}
