import clsx from "clsx";
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

  const pendingType = startAttack.isPending ? startAttack.variables : stopAttack.isPending ? stopAttack.variables : null;
  const mutationError = (startAttack.error as Error | null)?.message ?? (stopAttack.error as Error | null)?.message;

  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-base font-semibold uppercase tracking-[0.12em] text-ink">Attack scenarios</h2>
        {isError && <span className="text-sm text-danger">Sandbox control API unreachable</span>}
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {ATTACK_TYPES.map(({ id, label }) => {
          const running = status?.running?.[id] ?? false;
          const pending = pendingType === id;
          return (
            <div key={id} className="flex min-h-[200px] flex-col justify-between border border-line bg-white p-5 lg:aspect-square lg:min-h-0">
              <div>
                <span className="flex items-center gap-1.5 text-[13px] uppercase tracking-wide text-ink-muted">
                  <span className={clsx("h-2 w-2", running ? "bg-danger" : "bg-slate-300")} aria-hidden />
                  {isLoading ? "..." : running ? "Running" : "Idle"}
                </span>
                <span className="mt-6 block text-xl font-medium leading-snug text-ink">{label}</span>
              </div>
              <div className="flex flex-col gap-2">
                <button
                  onClick={() => startAttack.mutate(id)}
                  disabled={running || pending || isError}
                  className="flex-1 bg-ink px-3 py-1.5 text-sm font-semibold text-white transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-35"
                >
                  {pending && startAttack.variables === id ? "Starting..." : "Start"}
                </button>
                <button
                  onClick={() => stopAttack.mutate(id)}
                  disabled={!running || pending || isError}
                  className="flex-1 border border-line bg-white px-3 py-1.5 text-sm font-semibold text-ink transition-colors hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-35"
                >
                  {pending && stopAttack.variables === id ? "Stopping..." : "Stop"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      {mutationError && <p className="mt-2 text-sm text-danger">{mutationError}</p>}
    </section>
  );
}
