import { Badge, Card } from "../ui";
import { ATTACK_TYPES, useSandboxAttacksStatus, useStartAttack, useStopAttack } from "../../lib/sandboxApi";

/**
 * Start/stop controls for each Compose-profile-gated attack scenario.
 * Every action is a plain HTTP call to `globe/server.py` (via the
 * `/api/sandbox/*` proxy) -- this component has no knowledge of Docker,
 * `docker compose`, or container names; it only knows attack-type ids and
 * two REST verbs. `globe/server.py`'s own `/start` handler can take up to
 * ~120s (real `docker compose up`), so buttons show a pending state rather
 * than assuming an instant response.
 */
export function AttackControls() {
  const { data: status, isLoading, isError } = useSandboxAttacksStatus();
  const startAttack = useStartAttack();
  const stopAttack = useStopAttack();

  const pendingType = startAttack.isPending
    ? startAttack.variables
    : stopAttack.isPending
      ? stopAttack.variables
      : null;

  return (
    <Card>
      <h3 className="mb-3 text-xs font-medium text-slate-300">Attack scenarios</h3>
      {isError && (
        <p className="mb-2 text-xs text-danger">
          globe:8090 unreachable -- attack status/controls unavailable.
        </p>
      )}
      <div className="flex flex-col gap-2">
        {ATTACK_TYPES.map(({ id, label }) => {
          const running = status?.running?.[id] ?? false;
          const pending = pendingType === id;
          return (
            <div key={id} className="flex items-center justify-between gap-3 rounded-lg bg-white/5 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-200">{label}</span>
                <Badge tone={running ? "danger" : "neutral"}>
                  {isLoading ? "..." : running ? "running" : "idle"}
                </Badge>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => startAttack.mutate(id)}
                  disabled={running || pending || isError}
                  className="rounded-lg bg-accent/15 px-3 py-1 text-xs font-medium text-accent transition-colors hover:bg-accent/25 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {pending && startAttack.variables === id ? "Starting..." : "Start"}
                </button>
                <button
                  onClick={() => stopAttack.mutate(id)}
                  disabled={!running || pending || isError}
                  className="rounded-lg bg-white/10 px-3 py-1 text-xs font-medium text-slate-300 transition-colors hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {pending && stopAttack.variables === id ? "Stopping..." : "Stop"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      {(startAttack.isError || stopAttack.isError) && (
        <p className="mt-2 text-xs text-danger">
          {(startAttack.error as Error | undefined)?.message ?? (stopAttack.error as Error | undefined)?.message}
        </p>
      )}
    </Card>
  );
}
