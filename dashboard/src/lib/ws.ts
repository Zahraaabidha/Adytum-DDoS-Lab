import { useEffect, useRef } from "react";
import type { LiveThreatEvent } from "../types/threat";

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;

export type ConnectionStatus = "connecting" | "open" | "closed";

/**
 * Connects to threat-intel's `WebSocket /ws/threats` (proxied to `/ws` in
 * both dev and prod) and calls `onEvent` for every newly ingested IOC. Reconnects with
 * exponential backoff so a transient backend restart doesn't require a
 * page reload.
 *
 * Stage G bug fix: `onStatusChange` is new -- `threatStore.connectionStatus`/
 * `setConnectionStatus` were scaffolded in Stage E but this hook never
 * actually called it, so the store's status stayed stuck at its initial
 * "connecting" value forever even once the socket was genuinely open. This
 * went unnoticed until Stage G's Settings page became the first consumer
 * to display `connectionStatus` on screen. `onEvent` itself is unchanged.
 */
export function useThreatStream(
  onEvent: (event: LiveThreatEvent) => void,
  onStatusChange?: (status: ConnectionStatus) => void,
) {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const onStatusChangeRef = useRef(onStatusChange);
  onStatusChangeRef.current = onStatusChange;

  useEffect(() => {
    let socket: WebSocket | null = null;
    let backoff = INITIAL_BACKOFF_MS;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const connect = () => {
      if (stopped) return;
      onStatusChangeRef.current?.("connecting");
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/threats`);

      socket.onopen = () => {
        backoff = INITIAL_BACKOFF_MS;
        onStatusChangeRef.current?.("open");
      };

      socket.onmessage = (message) => {
        try {
          const parsed = JSON.parse(message.data) as LiveThreatEvent;
          onEventRef.current(parsed);
        } catch {
          // Malformed payloads are dropped, not surfaced -- a live feed
          // should degrade silently rather than crash the dashboard.
        }
      };

      socket.onclose = () => {
        if (stopped) return;
        onStatusChangeRef.current?.("closed");
        reconnectTimer = setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      };

      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    return () => {
      stopped = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);
}
