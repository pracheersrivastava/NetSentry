import {
  ArrowRight,
  FileCheck2,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import {
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { Snapshot, Anomaly, Flow } from "./types";
import {
  Panel,
  Badge,
  Empty,
  TextLink,
  priority,
  date,
  time,
} from "./components";

const colors = ["#da1e28", "#ff8389", "#f1c21b", "#24a148"];
export function AnomalyTable({
  events,
  flows,
  onSelect,
}: {
  events: Anomaly[];
  flows: Flow[];
  onSelect: (e: Anomaly) => void;
}) {
  return events.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Event / flow</th>
            <th>Source → destination</th>
            <th>Priority</th>
            <th>Score</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const f = flows.find((f) => f.flow_id === e.flow_id);
            return (
              <tr key={e.event_id}>
                <td>
                  <button className="row-link" onClick={() => onSelect(e)}>
                    {e.event_id}
                  </button>
                  <small>{e.flow_id}</small>
                </td>
                <td className="mono">
                  {f?.src_ip ?? "Unavailable"}
                  <small>
                    {f
                      ? `→ ${f.dst_ip}:${f.dst_port}`
                      : "Flow outside loaded window"}
                  </small>
                </td>
                <td>
                  <Badge value={priority(e.anomaly_score)} />
                </td>
                <td>
                  <span className={`score ${priority(e.anomaly_score)}`}>
                    {e.anomaly_score.toFixed(2)}
                  </span>
                </td>
                <td>
                  <Badge value={e.status} />
                </td>
                <td>
                  <button
                    className="table-open"
                    aria-label={`Open ${e.event_id}`}
                    onClick={() => onSelect(e)}
                  >
                    <ArrowRight size={16} />
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty title="No anomalies in this window" />
  );
}

export default function Overview({
  data,
  onNavigate,
  onSelect,
  onPriority,
}: {
  data: Snapshot;
  onNavigate: (p: string) => void;
  onSelect: (e: Anomaly) => void;
  onPriority: (p: string) => void;
}) {
  const active = data.anomalies.filter((a) => a.status !== "closed");
  const sev = ["critical", "high", "medium", "low"].map((name) => ({
    name,
    value: active.filter((a) => priority(a.anomaly_score) === name).length,
  }));
  const timestamps = data.flows.map((f) => date(f.timestamp).getTime());
  const end = Date.now(),
    start = Math.min(end - 3600000, ...timestamps);
  const width = Math.max(3600000, end - start) / 12;
  const activity = Array.from({ length: 12 }, (_, i) => {
    const from = start + i * width,
      to = from + width;
    const inBucket = (s: string) => {
      const t = date(s).getTime();
      return t >= from && (i === 11 ? t <= to : t < to);
    };
    return {
      time: new Date(from).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      flows: data.flows.filter((f) => inBucket(f.timestamp)).length,
      anomalies: data.anomalies.filter((a) => inBucket(a.created_at)).length,
    };
  });
  const stats = [
    {
      title: "Network flows",
      value: data.flows.length,
      note: "Loaded telemetry",
      tone: "flows",
    },
    {
      title: "Anomalies detected",
      value: data.anomalies.length,
      note: `${data.anomalies.filter((a) => a.status === "monitoring").length} under monitoring`,
      tone: "events",
    },
    {
      title: "Open investigations",
      value: data.investigations.filter(
        (i) => i.state !== "done" && i.state !== "failed",
      ).length,
      note: `${data.investigations.filter((i) => i.state === "done").length} completed`,
      tone: "cases",
    },
  ];
  return (
    <>
      <section className="metrics command-strip" aria-label="Network snapshot">
        {stats.map((s) => (
          <div className={`metric ${s.tone}`} key={s.title}>
            <span>{s.title}</span>
            <strong>{s.value}</strong>
            <small>{s.note}</small>
          </div>
        ))}
        <div className="score-policy">
          <span>Detection policy</span>
          <strong><b>{data.model.thresholds.monitor_at.toFixed(2)}</b> monitor <i /> <b>{data.model.thresholds.investigate_at.toFixed(2)}</b> investigate</strong>
        </div>
      </section>
      <div className="overview-grid">
        <Panel
          title="Network activity"
          meta="Flow volume and anomaly events"
          action={
            <div className="chart-legend">
              <span>
                <i className="teal-dot" />
                Flows
              </span>
              <span>
                <i className="amber-dot" />
                Anomalies
              </span>
            </div>
          }
        >
          <div className="activity-chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={activity}
                margin={{ top: 15, right: 15, left: -25, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="flowFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#78a9ff" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#78a9ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  stroke="#293440"
                  strokeDasharray="3 5"
                  vertical={false}
                />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#8797a7", fontSize: 10 }}
                  minTickGap={45}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "#8797a7", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#111923",
                    border: "1px solid #334353",
                    borderRadius: 2,
                    color: "#e1e8ec",
                  }}
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="flows"
                  name="Flows"
                  stroke="#78a9ff"
                  strokeWidth={2.5}
                  fill="url(#flowFill)"
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="anomalies"
                  name="Anomalies"
                  stroke="#f1c21b"
                  strokeWidth={2}
                  fill="transparent"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-footer">
            <span>
              <i className="status-dot" />
              {data.flows.length ? "Telemetry received" : "Awaiting telemetry"}
            </span>
            <span>
              {data.flows.length
                ? `Latest flow ${time(data.flows[0].timestamp)}`
                : "No flows ingested"}
            </span>
          </div>
        </Panel>
        <Panel title="Open signal" meta={`${active.length} active · ${sev[0].value} critical`}>
          <div className="severity-ledger">
            {sev.map((s, i) => (
              <button key={s.name} onClick={() => onPriority(s.name)}>
                <i style={{ background: colors[i] }} />
                <span>{humanPriority(s.name)}</span>
                <div className="severity-track"><b style={{ width: `${active.length ? Math.max(3, (s.value / active.length) * 100) : 0}%`, background: colors[i] }} /></div>
                <strong>{s.value}</strong>
              </button>
            ))}
            <div className="score-ruler">
              <div className="ruler-track"><i /><i /></div>
              <div className="ruler-values"><span>0.00</span><b>{data.model.thresholds.monitor_at.toFixed(2)}</b><b>{data.model.thresholds.investigate_at.toFixed(2)}</b><span>1.00</span></div>
              <div className="ruler-labels"><span>Store</span><span>Monitor</span><span>Investigate</span></div>
            </div>
          </div>
        </Panel>
      </div>
      <div className="overview-bottom">
        <Panel
          title="Recent anomalies"
          meta="Detection signals awaiting triage"
          action={
            <TextLink onClick={() => onNavigate("Anomalies")}>
              View all
            </TextLink>
          }
        >
          <AnomalyTable
            events={data.anomalies.slice(0, 5)}
            flows={data.flows}
            onSelect={onSelect}
          />
        </Panel>
        <Panel
          title="Investigation pipeline"
          meta="From detection to analyst review"
        >
          <div className="pipeline">
            {[
              {
                icon: ShieldAlert,
                title: "Detect",
                label: `${active.length} active · ${data.anomalies.length} total`,
                tone: "amber",
              },
              {
                icon: Workflow,
                title: "Investigate",
                label: `${data.investigations.filter((i) => i.state !== "done" && i.state !== "failed").length} in progress`,
                tone: "teal",
              },
              {
                icon: FileCheck2,
                title: "Review",
                label: `${data.investigations.filter((i) => i.state === "done").length} completed cases`,
                tone: "blue",
              },
            ].map((s, i) => (
              <button
                key={s.title}
                onClick={() =>
                  onNavigate(
                    i === 0
                      ? "Anomalies"
                      : i === 1
                        ? "Investigations"
                        : "Reports",
                  )
                }
              >
                <span className={`pipeline-icon ${s.tone}`}>
                  <s.icon size={19} />
                </span>
                <div>
                  <strong>{s.title}</strong>
                  <small>{s.label}</small>
                </div>
                <ArrowRight size={16} />
              </button>
            ))}
          </div>
          <div className="threshold-note">
            <span>Detection boundaries</span>
            <div>
              <strong>{data.model.thresholds.monitor_at.toFixed(2)}</strong>
              <span>Monitor</span>
              <strong>{data.model.thresholds.investigate_at.toFixed(2)}</strong>
              <span>Investigate</span>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}
function humanPriority(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
