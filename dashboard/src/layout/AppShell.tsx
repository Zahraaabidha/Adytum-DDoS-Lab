import type { ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { TopNav } from "./TopNav";
import { NAV_ITEMS } from "./navItems";
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
  const { pathname } = useLocation();
  const current = NAV_ITEMS.find((item) => (item.end ? pathname === item.to : pathname.startsWith(item.to)));

  return (
    <div className="flex min-h-full flex-col">
      <TopNav />
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8 md:py-8">
        <div className="mx-auto w-full max-w-[1400px]">
          {current && (
            <h1 className="mb-6 border-b border-line pb-4 text-xl font-semibold tracking-tight text-ink md:text-2xl">
              {current.label}
            </h1>
          )}
          {children}
        </div>
      </main>
    </div>
  );
}
