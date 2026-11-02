import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { Badge, Card, EmptyState } from "../components/ui";
import { SEVERITY_LABEL, SEVERITY_TONE } from "../components/feed/labels";
import { isPrivateIp, KIND_HELP, KIND_LABEL, relatedIncident, useUnifiedAlerts, type UnifiedAlert } from "../lib/alerts";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b border-line py-2 text-sm last:border-b-0">
      <dt className="shrink-0 text-ink-muted">{label}</dt>
      <dd className="min-w-0 break-words text-right text-ink">{children}</dd>
    </div>
  );
}

const fmt = (ms: number) => new Date(ms).toLocaleString();

function SectionTitle({ children }: { children: ReactNode }) {
  return <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-muted">{children}</h3>;
}

export function AlertDetail() {
  const { id = "" } = useParams();
  const { alerts, isLoading } = useUnifiedAlerts();
  const alert = alerts.find((a) => a.id === id);

  if (!alert) {
    return (
      <div className="flex flex-col gap-4">
        <Link to="/alerts" className="text-sm text-accent hover:underline">
          &larr; Back to alerts
        </Link>
        {isLoading ? (
          <p className="text-xs text-ink-muted">Loading...</p>
        ) : (
          <EmptyState
            title="Alert not found"
            hint="It is no longer in the recent window the services return, or the link is incorrect."
          />
        )}
      </div>
    );
  }

  const s = alert.suricata;
  const i = alert.incident;
  const e = alert.intel;
  const related = relatedIncident(alert, alerts);

  return (
    <div className="flex flex-col gap-5">
      <Link to="/alerts" className="text-sm text-accent hover:underline">
        &larr; Back to alerts
      </Link>

      <div className="border border-line bg-white p-5">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={alert.kind === "intel" ? "neutral" : "accent"}>{KIND_LABEL[alert.kind]}</Badge>
          <Badge tone={SEVERITY_TONE[alert.severity]}>{SEVERITY_LABEL[alert.severity]}</Badge>
        </div>
        <h2 className="mt-3 text-xl font-semibold text-ink">{alert.title}</h2>
        <p className="mt-1 text-sm text-ink-muted">{KIND_HELP[alert.kind]}</p>
        {alert.severity === "unclassified" && (
          <p className="mt-2 text-xs text-ink-muted">
            Unclassified: the source did not publish a severity for this item, so none is assumed.
          </p>
        )}
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <SectionTitle>Overview</SectionTitle>
          <dl>
            <Field label="Time">{fmt(alert.time)}</Field>
            <Field label="Source">{alert.source}</Field>
            {i && <Field label="Status">{i.status}</Field>}
            {i && <Field label="Ended">{fmt(i.end * 1000)}</Field>}
            {i && <Field label="Duration">{i.duration_s.toFixed(0)} s</Field>}
            {s && <Field label="Signature ID">{s.signature_id ?? "n/a"}</Field>}
            {s?.category && <Field label="Category">{s.category}</Field>}
            {s && <Field label="Action">{s.action ?? "n/a"}</Field>}
            {s && <Field label="Suricata severity">{`${s.severity} (${s.severity_label})`}</Field>}
            {e && <Field label="First seen">{fmt(new Date(e.first_seen).getTime())}</Field>}
            {e && <Field label="Feed confidence">{Math.round(e.confidence_score * 100)}%</Field>}
            {e && <Field label="Reporting sources">{e.source_count}</Field>}
          </dl>
        </Card>

        <Card>
          <SectionTitle>IP information</SectionTitle>
          {s && (
            <dl>
              <Field label="Source">
                <IpValue ip={s.src_ip} />
                {s.src_port != null && `:${s.src_port}`}
              </Field>
              <Field label="Destination">
                <IpValue ip={s.dest_ip} />
                {s.dest_port != null && `:${s.dest_port}`}
              </Field>
              <Field label="Protocol">
                {s.protocol}
                {s.app_proto ? ` / ${s.app_proto}` : ""}
              </Field>
              <Field label="Seen on">{s.interfaces.join(", ") || s.in_iface || "n/a"}</Field>
            </dl>
          )}
          {e && (
            <dl>
              <Field label={e.ioc_type.toUpperCase()}>{e.ioc}</Field>
              <Field label="Country">{e.country ?? "Unknown"}</Field>
              <Field label="ASN">{e.asn ?? "Unknown"}</Field>
              <Field label="Organization">{e.organization ?? "Unknown"}</Field>
              {e.lat != null && e.lon != null && <Field label="Coordinates">{`${e.lat.toFixed(2)}, ${e.lon.toFixed(2)}`}</Field>}
            </dl>
          )}
          {i && (
            <dl>
              {i.detectors.suricata.sources.length === 0 && <Field label="Source IPs">None recorded</Field>}
              {i.detectors.suricata.sources.map((src) => (
                <Field key={src.ip} label={`${src.alerts} alert${src.alerts === 1 ? "" : "s"}`}>
                  <IpValue ip={src.ip} />
                </Field>
              ))}
            </dl>
          )}
        </Card>
      </div>

      {s && (
        <Card>
          <SectionTitle>Evidence</SectionTitle>
          <dl>
            <Field label="ML detector at this time">
              {!s.ml.ml_available || s.ml.confidence == null
                ? "No sample recorded"
                : `${s.ml.ml_flagged ? "Flagged" : "Not flagged"} (${(s.ml.confidence * 100).toFixed(0)}% confidence)`}
            </Field>
            {s.ml.request_rate != null && <Field label="Request rate">{s.ml.request_rate.toFixed(1)} req/s</Field>}
            {s.ml.threshold_rps != null && <Field label="Rate limit at the time">{s.ml.threshold_rps} req/s</Field>}
            {s.ml.policy_state && <Field label="Mitigation state">{s.ml.policy_state}</Field>}
            {s.hop_alerts > 0 && <Field label="Merged sightings">{s.hop_alerts} duplicate(s) merged</Field>}
          </dl>
          <p className="mt-3 text-xs text-ink-muted">Suricata alerts are advisory; they never trigger mitigation on their own.</p>
        </Card>
      )}

      {i && <IncidentEvidence incident={i} />}

      {s && (
        <Card>
          <SectionTitle>Related incident</SectionTitle>
          {related ? (
            <p className="text-sm text-ink">
              <Link to={`/alerts/${encodeURIComponent(`incident-${related.id}`)}`} className="text-accent hover:underline">
                {related.title}
              </Link>{" "}
              <span className="text-ink-muted">
                ({related.severity} severity, {related.status}). Matched by time window and signature, not by flow.
              </span>
            </p>
          ) : (
            <p className="text-sm text-ink-muted">No correlated incident covers this alert in the current window.</p>
          )}
        </Card>
      )}
    </div>
  );
}

function IpValue({ ip }: { ip: string }) {
  return (
    <span className="font-mono">
      {ip}
      {isPrivateIp(ip) && <span className="ml-2 font-sans text-xs text-ink-muted">(private/internal, no GeoIP)</span>}
    </span>
  );
}

const ASSESSMENT: Record<string, string> = {
  corroborated: "Suricata and the ML detector agree",
  suricata_only: "Suricata only; the ML detector did not flag",
  suricata_ml_unavailable: "Suricata only; ML data unavailable",
  ml_only: "ML detector only; no Suricata alert",
  ml_only_suricata_unavailable: "ML detector only; Suricata unavailable",
};

function IncidentEvidence({ incident: i }: { incident: NonNullable<UnifiedAlert["incident"]> }) {
  return (
    <Card>
      <SectionTitle>Evidence</SectionTitle>
      <dl>
        <Field label="Assessment">{ASSESSMENT[i.assessment] ?? i.assessment}</Field>
        <Field label="Suricata">
          {i.detectors.suricata.state === "flagged"
            ? `${i.detectors.suricata.alerts} alert(s): ${i.detectors.suricata.signatures.map((x) => x.replace("SENTINEL LAB: ", "")).join(", ")}`
            : i.detectors.suricata.state === "not_flagged"
              ? "No alerts"
              : "No data"}
        </Field>
        <Field label="Isolation Forest">
          {i.detectors.ml.state === "flagged"
            ? `Flagged ${i.detectors.ml.flagged_polls} of ${i.detectors.ml.polls} polls` +
              (i.detectors.ml.peak_confidence != null ? `, peak ${(i.detectors.ml.peak_confidence * 100).toFixed(0)}%` : "")
            : i.detectors.ml.state === "not_flagged"
              ? "Not flagged"
              : "No data"}
        </Field>
        {i.metrics.state === "elevated" && i.metrics.peak != null && (
          <Field label="Metric">{`${i.metrics.metric ?? "metric"} peaked at ${i.metrics.peak}${i.metrics.unit ? ` ${i.metrics.unit}` : ""}`}</Field>
        )}
        <Field label="Rate limit">{i.mitigation.cap_lowered ? `Lowered to ${i.mitigation.min_cap_rps} req/s` : "Not lowered"}</Field>
      </dl>
      {i.evidence.length > 0 && (
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-ink-soft">
          {i.evidence.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {i.caveats.length > 0 && (
        <div className="mt-4 border-l-2 border-line pl-3">
          <p className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">Caveats</p>
          <ul className="mt-1 space-y-1 text-xs text-ink-muted">
            {i.caveats.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
