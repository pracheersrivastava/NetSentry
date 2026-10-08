import { ArrowUpRight, Network, Radio, Activity, Database } from "lucide-react";
import type { Snapshot } from "./types";
import { Empty, Panel } from "./components";

export default function TrafficAnalytics({
  data,
  onSource,
}: {
  data: Snapshot;
  onSource: (ip: string) => void;
}) {
  const totalBytes = data.flows.reduce(
    (sum, f) => sum + (f.features.total_bytes ?? 0),
    0,
  );
  const packets = data.flows.reduce(
    (sum, f) => sum + (f.features.orig_pkts ?? 0) + (f.features.resp_pkts ?? 0),
    0,
  );
  const protocols = new Map<string, number>();
  const ports = new Map<number, number>();
  const sources = new Map<
    string,
    { flows: number; bytes: number; anomalies: number }
  >();
  const anomalyFlows = new Set(data.anomalies.map((a) => a.flow_id));
  for (const flow of data.flows) {
    protocols.set(flow.protocol, (protocols.get(flow.protocol) ?? 0) + 1);
    ports.set(flow.dst_port, (ports.get(flow.dst_port) ?? 0) + 1);
    const source = sources.get(flow.src_ip) ?? {
      flows: 0,
      bytes: 0,
      anomalies: 0,
    };
    source.flows++;
    source.bytes += flow.features.total_bytes ?? 0;
    if (anomalyFlows.has(flow.flow_id)) source.anomalies++;
    sources.set(flow.src_ip, source);
  }
  const stats = [
    { title: "Source hosts", value: sources.size, icon: Network },
    {
      title: "Destination hosts",
      value: new Set(data.flows.map((f) => f.dst_ip)).size,
      icon: Radio,
    },
    { title: "Transferred", value: bytes(totalBytes), icon: Database },
    {
      title: "Packets observed",
      value: packets.toLocaleString(),
      icon: Activity,
    },
  ];
  return (
    <>
      <div className="metrics">
        {stats.map((s) => (
          <section className="metric" key={s.title}>
            <div>
              <span>{s.title}</span>
              <s.icon size={18} />
            </div>
            <strong>{s.value}</strong>
            <p>Loaded telemetry window</p>
          </section>
        ))}
      </div>
      <div className="system-grid">
        <Panel
          title="Protocol distribution"
          meta={`${data.flows.length} network flows`}
        >
          {data.flows.length ? (
            <div className="distribution">
              {Array.from(protocols)
                .sort((a, b) => b[1] - a[1])
                .map(([name, count], i) => (
                  <div key={name}>
                    <div>
                      <span>{name}</span>
                      <strong>
                        {count}
                        <small>
                          {" "}
                          · {Math.round((count / data.flows.length) * 100)}%
                        </small>
                      </strong>
                    </div>
                    <div className="distribution-track">
                      <span
                        style={{
                          width: `${(count / data.flows.length) * 100}%`,
                          background: ["#78a9ff", "#f1c21b", "#8a3ffc"][i % 3],
                        }}
                      />
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <Empty title="No protocol data" />
          )}
        </Panel>
        <Panel
          title="Destination ports"
          meta="Most frequently observed services"
        >
          {data.flows.length ? (
            <div className="distribution">
              {Array.from(ports)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 6)
                .map(([port, count]) => (
                  <div key={port}>
                    <div>
                      <span className="mono">
                        {port}
                        <small>
                          {" "}
                          {(
                            {
                              443: "HTTPS",
                              80: "HTTP",
                              22: "SSH",
                              53: "DNS",
                              8080: "HTTP alternate",
                            } as Record<number, string>
                          )[port] ?? ""}
                        </small>
                      </span>
                      <strong>{count} flows</strong>
                    </div>
                    <div className="distribution-track">
                      <span
                        style={{
                          width: `${(count / data.flows.length) * 100}%`,
                          background: "var(--accent)",
                        }}
                      />
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <Empty title="No service data" />
          )}
        </Panel>
      </div>
      <Panel
        title="Top talkers"
        meta="Source hosts by transferred bytes"
        className="traffic-sources"
      >
        {sources.size ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source host</th>
                  <th>Flows</th>
                  <th>Transferred</th>
                  <th>Anomalies</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {Array.from(sources)
                  .sort((a, b) => b[1].bytes - a[1].bytes)
                  .slice(0, 15)
                  .map(([ip, s]) => (
                    <tr
                      key={ip}
                      className="clickable-row"
                      tabIndex={0}
                      aria-label={`View flows from ${ip}`}
                      onClick={() => onSource(ip)}
                      onKeyDown={(ev) => {
                        if (ev.key === "Enter" || ev.key === " ") {
                          ev.preventDefault();
                          onSource(ip);
                        }
                      }}
                    >
                      <td>
                        <span className="row-link">{ip}</span>
                      </td>
                      <td>{s.flows}</td>
                      <td>{bytes(s.bytes)}</td>
                      <td>{s.anomalies}</td>
                      <td>
                        <span className="table-open" aria-hidden="true">
                          <ArrowUpRight size={16} />
                        </span>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No source hosts observed" />
        )}
      </Panel>
    </>
  );
}
function bytes(n: number) {
  return n >= 1e9
    ? `${(n / 1e9).toFixed(2)} GB`
    : n >= 1e6
      ? `${(n / 1e6).toFixed(2)} MB`
      : n >= 1e3
        ? `${(n / 1e3).toFixed(1)} KB`
        : `${n} B`;
}
