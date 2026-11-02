import { Badge, Card } from "../ui";
import { useCorrelation } from "../../lib/queries";

/**
 * Stage I: the one deliberate integration seam between the Global Threat
 * Intelligence module and the Sandbox Lab (`GET /api/threats/correlation`,
 * `services/threat-intel/app/correlation/engine.py`). Mounted on Overview
 * rather than either module's own page, since it represents the
 * relationship *between* the two rather than belonging to one of them
 * (PROJECT_EXECUTION_PLAN.md Stage I).
 *
 * The `disclaimer` line is rendered unconditionally whenever the backend
 * has returned a response at all (available or not) -- it is never hidden
 * behind a toggle or collapsed section, per the explicit requirement that
 * every response carry a permanent "behavioral similarity only, not
 * attribution" notice alongside the score.
 */
export function CorrelationPanel() {
  const { data, isLoading, isError } = useCorrelation();

  return (
    <Card>
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-ink">Sandbox &harr; Threat Intel correlation</h2>
        <Badge tone="neutral">Heuristic</Badge>
      </div>

      {isLoading && <p className="mt-3 text-xs text-ink-muted">Computing correlation...</p>}

      {isError && !isLoading && (
        <p className="mt-3 text-xs text-ink-muted">Correlation endpoint (threat-intel) is unreachable right now.</p>
      )}

      {!isLoading && !isError && data && (
        <div className="mt-3 flex flex-col gap-3">
          {data.available ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-semibold text-ink">
                  {data.correlation_percentage?.toFixed(0)}%
                </span>
                <span className="text-xs text-ink-muted">behavioral similarity</span>
              </div>
              <p className="text-sm text-ink-soft">{data.observation}</p>
              {data.matched_features.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {data.matched_features.map((feature) => (
                    <Badge key={feature} tone="accent">
                      {feature}
                    </Badge>
                  ))}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-ink-soft">{data.observation}</p>
          )}
          <p className="border-t border-line pt-2 text-xs italic text-ink-muted">{data.disclaimer}</p>
        </div>
      )}
    </Card>
  );
}
