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
/** Large page title; the last word picks up the teal accent. */
function PageTitle({ label }: { label: string }) {
  const words = label.split(" ");
  const last = words.pop();
  return (
    <h1 className="mb-8 text-3xl font-medium leading-tight tracking-tight text-ink md:mb-10 md:text-5xl">
      {words.length > 0 && `${words.join(" ")} `}
      <span className={words.length > 0 ? "text-accent" : undefined}>{last}</span>
    </h1>
  );
}

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
          {current && <PageTitle label={current.label} />}
          {children}
        </div>
      </main>
    </div>
  );
}
