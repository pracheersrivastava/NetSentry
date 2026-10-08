import {
  Check,
  Download,
  FileText,
  LoaderCircle,
  Microscope,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import type {
  Investigation,
  Evidence,
  Report,
  Anomaly,
  Hypothesis,
} from "./types";
import { Badge, Panel, human, time, date, download, Empty } from "./components";

export default function CaseView({
  inv,
  evidence,
  report,
  loading,
  onReport,
  onReview,
  busy,
  event,
  threshold,
}: {
  inv: Investigation;
  evidence: Evidence[];
  report: Report | null;
  loading: boolean;
  onReport: boolean;
  onReview: (status: string) => void;
  busy: boolean;
  event?: Anomaly;
  threshold: number;
}) {
  const initial = evidence.find((e) => e.source_tool === "feature_attribution");
  const risk = evidence.find((e) => e.source_tool === "risk_assessor");
  const payload = report?.report_json;
  const validator = evidence.find(
    (e) => e.source_tool === "hypothesis_validator",
  );
  const hypotheses =
    payload?.hypotheses ??
    (Array.isArray(validator?.payload.hypotheses)
      ? (validator.payload.hypotheses as Hypothesis[])
      : []);
  const tools = evidence.filter(
    (e) =>
      ![
        "feature_attribution",
        "hypothesis_validator",
        "risk_assessor",
      ].includes(e.source_tool),
  );
  return (
    <>
      <div className="case-summary">
        <div>
          <span className="eyebrow">
            {onReport ? "INCIDENT REPORT" : "INVESTIGATION WORKSPACE"}
          </span>
          <h2>
            {onReport
              ? (report?.report_id ?? "Report unavailable")
              : inv.investigation_id}
          </h2>
          <p>
            {inv.event_id} <span> / </span>{" "}
            {date(
              onReport && report ? report.generated_at : inv.started_at,
            ).toLocaleDateString()}{" "}
            · {time(onReport && report ? report.generated_at : inv.started_at)}
          </p>
        </div>
        <Badge
          value={onReport ? (report?.reviewer_status ?? "pending") : inv.state}
        />
        {report && (
          <button
            className="button"
            onClick={() => download(`${report.report_id}.json`, report)}
          >
            <Download size={16} />
            Export JSON
          </button>
        )}
      </div>
      {loading ? (
        <Empty title="Loading case evidence..." />
      ) : onReport && payload ? (
        <div className="report-layout">
          <article className="report-document">
            <div className="report-title">
              <ShieldAlert size={25} />
              <div>
                <span className="eyebrow">NETSENTRY / ANALYST CASE REPORT</span>
                <h2>Incident assessment</h2>
              </div>
              <Badge value={payload.severity} />
            </div>
            <section>
              <h3>Summary & findings</h3>
              {payload.findings.map((s, i) => (
                <p key={i}>{s}</p>
              ))}
            </section>
            <section>
              <h3>Observed facts</h3>
              <ul>
                {payload.observed_facts.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </section>
            <section>
              <h3>Hypotheses</h3>
              {payload.hypotheses.map((h, i) => (
                <div className="hypothesis" key={i}>
                  <div>
                    <strong>{human(h.hypothesis)}</strong>
                    <Badge value={h.status} />
                  </div>
                  <p>{h.evidence_summary}</p>
                  {h.confidence != null && (
                    <small>{Math.round(h.confidence * 100)}% confidence</small>
                  )}
                </div>
              ))}
            </section>
            <section>
              <h3>Uncertainties</h3>
              <ul>
                {payload.uncertainties.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </section>
            <section>
              <h3>Recommended next steps</h3>
              <ol>
                {payload.recommended_next_steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </section>
            <section>
              <h3>Supporting evidence</h3>
              {evidence.map((e) => (
                <details key={e.evidence_id} className="evidence-detail">
                  <summary>
                    <span>{e.source_tool}</span>
                    <small>{e.evidence_id}</small>
                  </summary>
                  <JsonEvidence value={e.payload} />
                </details>
              ))}
            </section>
          </article>
          <div>
            <Panel title="Risk assessment">
              <div className="risk-value">
                <strong>
                  {Math.round(payload.confidence * 100)}
                  <small>%</small>
                </strong>
                <span>Assessment confidence</span>
              </div>
              <p className="muted prose">
                {payload.risk_assessment?.rationale}
              </p>
              <dl className="facts">
                <div>
                  <dt>Detection severity</dt>
                  <dd>
                    <Badge value={payload.severity} />
                  </dd>
                </div>
                <div>
                  <dt>Assessed risk</dt>
                  <dd>
                    {human(payload.risk_assessment?.level ?? "unavailable")}
                  </dd>
                </div>
                <div>
                  <dt>Composite risk</dt>
                  <dd>
                    {payload.risk_assessment?.composite_score?.toFixed(2) ??
                      "Unavailable"}
                  </dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Detection">
              <dl className="facts">
                <div>
                  <dt>Event</dt>
                  <dd className="mono">{inv.event_id}</dd>
                </div>
                <div>
                  <dt>Score</dt>
                  <dd>{event?.anomaly_score.toFixed(2) ?? "Unavailable"}</dd>
                </div>
                <div>
                  <dt>Model version</dt>
                  <dd>{event?.model_version ?? "Unavailable"}</dd>
                </div>
                <div>
                  <dt>Investigation boundary</dt>
                  <dd>{threshold.toFixed(2)}</dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Analyst review">
              <Badge value={report!.reviewer_status} />
              <div className="review-actions">
                <button
                  className="button primary"
                  disabled={busy}
                  onClick={() => onReview("approved")}
                >
                  <Check size={16} />
                  Approve report
                </button>
                <button
                  className="button"
                  disabled={busy}
                  onClick={() => onReview("rejected")}
                >
                  Reject report
                </button>
                <button
                  className="text-link"
                  disabled={busy}
                  onClick={() => onReview("pending")}
                >
                  Return to pending
                </button>
              </div>
            </Panel>
            {!!payload.mitre_techniques?.length && (
              <Panel title="MITRE ATT&CK">
                {payload.mitre_techniques.map((t) => (
                  <div className="mitre" key={t.id}>
                    <span>{t.id}</span>
                    <strong>{t.name}</strong>
                    <small>{t.tactic}</small>
                  </div>
                ))}
              </Panel>
            )}
          </div>
        </div>
      ) : onReport ? (
        <Empty
          title="No report available"
          text="The investigation has not produced a report."
        />
      ) : (
        <div className="investigation-layout">
          <div className="timeline">
            <Timeline
              title="Alert received"
              subtitle={inv.event_id}
              icon={<ShieldAlert size={18} />}
              done
            >
              <Badge value={inv.state} />
            </Timeline>
            <Timeline
              title="Initial analysis"
              subtitle="Feature signals and baseline deviations"
              icon={<Microscope size={18} />}
              done={!!initial}
            >
              {initial ? (
                <InitialAnalysis value={initial.payload} />
              ) : (
                <p className="muted">No initial analysis evidence recorded.</p>
              )}
            </Timeline>
            <Timeline
              title="Evidence gathering"
              subtitle={`${tools.length} recorded tool results`}
              icon={<Workflow size={18} />}
              done={tools.length > 0}
            >
              {tools.map((e) => (
                <details className="evidence-detail" key={e.evidence_id}>
                  <summary>
                    <span>
                      <Check size={14} />
                      {e.source_tool}
                    </span>
                    <small>{time(e.timestamp)}</small>
                  </summary>
                  <JsonEvidence value={e.payload} />
                </details>
              ))}
            </Timeline>
            <Timeline
              title="Hypothesis validation"
              subtitle="Tested against collected evidence"
              icon={<Microscope size={18} />}
              done={
                !!evidence.find((e) => e.source_tool === "hypothesis_validator")
              }
            >
              {hypotheses.map((h, i) => (
                <div className="hypothesis" key={i}>
                  <div>
                    <strong>{human(h.hypothesis)}</strong>
                    <Badge value={h.status} />
                  </div>
                  <p>{h.evidence_summary}</p>
                </div>
              ))}
            </Timeline>
            <Timeline
              title="Risk assessment"
              subtitle="Deterministic evidence weighting"
              icon={<ShieldAlert size={18} />}
              done={!!risk}
            >
              {payload?.risk_assessment?.rationale && (
                <p>{payload.risk_assessment.rationale}</p>
              )}
              {risk && (
                <details className="evidence-detail">
                  <summary>Risk factors</summary>
                  <JsonEvidence value={risk.payload} />
                </details>
              )}
            </Timeline>
            <Timeline
              title="Incident report"
              subtitle={report?.report_id ?? "Awaiting report"}
              icon={<FileText size={18} />}
              done={!!report}
            >
              {report && <p>{payload?.findings[0]}</p>}
            </Timeline>
          </div>
          <aside>
            <Panel title="Case details">
              <dl className="facts">
                <div>
                  <dt>Status</dt>
                  <dd>
                    <Badge value={inv.state} />
                  </dd>
                </div>
                <div>
                  <dt>Evidence records</dt>
                  <dd>{evidence.length}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>
                    {payload
                      ? `${Math.round(payload.confidence * 100)}%`
                      : "Unavailable"}
                  </dd>
                </div>
                <div>
                  <dt>Completed</dt>
                  <dd>
                    {inv.completed_at ? time(inv.completed_at) : "In progress"}
                  </dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Tool trace">
              <div className="trace">
                {evidence.map((e, i) => (
                  <div key={e.evidence_id}>
                    <span>{String(i + 1).padStart(2, "0")}</span>
                    <code>{e.source_tool}</code>
                  </div>
                ))}
              </div>
            </Panel>
          </aside>
        </div>
      )}
    </>
  );
}
function JsonEvidence({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}
function InitialAnalysis({ value }: { value: Record<string, unknown> }) {
  const attrs = Array.isArray(value.attributions)
    ? (value.attributions as {
        feature: string;
        value: number | string;
        signal: string;
        severity: string;
      }[])
    : [];
  return attrs.length ? (
    <div className="analysis-signals">
      {attrs.map((a, i) => (
        <div key={i}>
          <div>
            <strong>{a.signal}</strong>
            <small>
              {human(a.feature)} · {String(a.value)}
            </small>
          </div>
          <Badge value={a.severity} />
        </div>
      ))}
    </div>
  ) : (
    <p className="muted">No feature deviations recorded.</p>
  );
}
function Timeline({
  title,
  subtitle,
  icon,
  done,
  children,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  done: boolean;
  children: React.ReactNode;
}) {
  return (
    <section className={`timeline-step ${done ? "complete" : ""}`}>
      <span className="timeline-icon">
        {done ? <Check size={18} /> : <LoaderCircle size={18} />}
      </span>
      <div className="timeline-content">
        <div className="timeline-heading">
          {icon}
          <h3>{title}</h3>
        </div>
        <small>{subtitle}</small>
        <div className="timeline-body">{children}</div>
      </div>
    </section>
  );
}
