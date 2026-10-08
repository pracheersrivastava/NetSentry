import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Bell,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Download,
  FlaskConical,
  LayoutDashboard,
  LockKeyhole,
  LoaderCircle,
  Menu,
  Network,
  Radio,
  RefreshCw,
  Settings2,
  Shield,
  ShieldAlert,
  Upload,
  Workflow,
  X,
} from "lucide-react";
import type {
  Anomaly,
  Evidence,
  Flow,
  Investigation,
  Report,
  Snapshot,
} from "./types";
import * as api from "./api";
import {
  Badge,
  Drawer,
  Empty,
  IconButton,
  Panel,
  ScoreGauge,
  SearchBox,
  date,
  download,
  human,
  featureName,
  featureValue,
  priority,
  time,
} from "./components";
import {
  anomalySearchText,
  caseSecondary,
  decisionFromScore,
  decisionShort,
  flowHeadline,
} from "./copy";
import Overview, { AnomalyTable } from "./Overview";
import CaseView from "./CaseView";
import TrafficAnalytics from "./TrafficAnalytics";
import ModelWorkbench from "./ModelWorkbench";

const nav = [
  {
    group: "Workspace",
    items: [
      ["Overview", LayoutDashboard],
      ["Flows", Network],
      ["Import", Upload],
      ["Traffic Analytics", Activity],
    ],
  },
  {
    group: "Detection",
    items: [
      ["Anomalies", ShieldAlert],
      ["Model", FlaskConical],
    ],
  },
  {
    group: "Cases",
    items: [["Cases", Workflow]],
  },
  {
    group: "System",
    items: [
      ["API Health", Radio],
      ["Settings", Settings2],
      ["Privacy Policy", LockKeyhole],
    ],
  },
] as const;
const descriptions: Record<string, string> = {
  Overview: "Imported traffic, anomaly queue, and cases.",
  Flows: "Imported and scored traffic.",
  Import: "Submit normalized flow records to the detector.",
  "Traffic Analytics": "Traffic patterns across the loaded telemetry window.",
  Anomalies: "Events above the monitor threshold, ready for triage.",
  Cases: "Evidence, report, and review for each investigation.",
  Model: "Active detector and how scoring works.",
  "API Health": "Service availability and investigation capabilities.",
  Settings: "Workspace and refresh preferences.",
  "Privacy Policy": "How this self-hosted console handles telemetry.",
};
const pageTitles: Record<string, string> = {
  Overview: "Security overview",
  Flows: "Flows",
  Import: "Import flows",
  "Traffic Analytics": "Traffic analytics",
  Anomalies: "Anomalies",
  Cases: "Cases",
  Model: "Model",
  "API Health": "API health",
  Settings: "Settings",
  "Privacy Policy": "Privacy policy",
};
type CaseTab = "evidence" | "report" | "review";

async function readFlowFile(file: File): Promise<api.FlowImport[]> {
  if (!/\.(json|jsonl|ndjson)$/i.test(file.name)) {
    throw new Error("Choose a .json, .jsonl, or .ndjson flow file");
  }
  if (file.size > 10 * 1024 * 1024) throw new Error("Files are limited to 10 MB");
  const text = await file.text();
  const rows = /\.(jsonl|ndjson)$/i.test(file.name)
    ? text.split(/\r?\n/).filter((line) => line.trim()).map((line) => JSON.parse(line))
    : (() => {
        const parsed = JSON.parse(text);
        return Array.isArray(parsed) ? parsed : [parsed];
      })();
  if (!rows.length) throw new Error("The file contains no flow records");
  if (rows.length > 5000) throw new Error("Import up to 5,000 flows at a time");
  for (const [index, row] of rows.entries()) {
    if (
      !row ||
      typeof row !== "object" ||
      typeof row.src_ip !== "string" ||
      typeof row.dst_ip !== "string" ||
      !Number.isInteger(row.src_port) ||
      !Number.isInteger(row.dst_port)
    ) {
      throw new Error(`Record ${index + 1} needs src_ip, dst_ip, src_port, and dst_port`);
    }
  }
  return rows as api.FlowImport[];
}

export default function App() {
  const [page, setPage] = useState("Overview"),
    [data, setData] = useState<Snapshot | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [query, setQuery] = useState(""),
    [range, setRange] = useState("24"),
    [status, setStatus] = useState("all"),
    [minScore, setMinScore] = useState(false),
    [flowPage, setFlowPage] = useState(0),
    [selectedFlow, setSelectedFlow] = useState<Flow | null>(null),
    [selectedEvent, setSelectedEvent] = useState<Anomaly | null>(null),
    [inv, setInv] = useState<Investigation | null>(null),
    [caseTab, setCaseTab] = useState<CaseTab>("evidence"),
    [ev, setEv] = useState<Evidence[]>([]),
    [rep, setRep] = useState<Report | null>(null),
    [caseLoading, setCaseLoading] = useState(false),
    [busy, setBusy] = useState(false),
    [mobile, setMobile] = useState(false),
    [autoRefresh, setAutoRefresh] = useState(true),
    [notice, setNotice] = useState("");
  const [importResult, setImportResult] = useState<{ filename: string; results: api.IngestResult[] } | null>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState("");
  const caseGeneration = useRef(0),
    fetching = useRef(false),
    busyRef = useRef(false);
  const [offline, setOffline] = useState(true);
  const [eventFlow, setEventFlow] = useState<Flow | null>(null);
  const detailGeneration = useRef(0);
  const [priorityFilter, setPriorityFilter] = useState("all");
  const refresh = useCallback(async () => {
    if (fetching.current || busyRef.current) return;
    fetching.current = true;
    try {
      const next = await api.snapshot();
      if (busyRef.current) return;
      setData(next);
      setLastRefresh(new Date());
      setError("");
      setOffline(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to reach backend");
      setOffline(true);
    } finally {
      fetching.current = false;
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    if (!autoRefresh) return;
    const t = setInterval(() => void refresh(), 15000);
    return () => clearInterval(t);
  }, [refresh, autoRefresh]);
  useEffect(() => {
    const close = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobile(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(""), 4500);
    return () => clearTimeout(t);
  }, [notice]);
  function navigate(p: string) {
    detailGeneration.current++;
    setPriorityFilter("all");
    setPage(p);
    setQuery("");
    setStatus("all");
    setMinScore(false);
    setFlowPage(0);
    setMobile(false);
    setInv(null);
    caseGeneration.current++;
    setSelectedEvent(null);
    setSelectedFlow(null);
    setCaseTab("evidence");
  }
  const filtered = useMemo(() => {
    if (!data) return null;
    const cutoff = range === "all" ? 0 : Date.now() - Number(range) * 3600000;
    return {
      ...data,
      flows: data.flows.filter((f) => date(f.timestamp).getTime() >= cutoff),
      anomalies: data.anomalies.filter(
        (e) => date(e.created_at).getTime() >= cutoff,
      ),
      investigations: data.investigations.filter(
        (i) => date(i.started_at).getTime() >= cutoff,
      ),
    };
  }, [data, range]);
  const thresholds = data?.model.thresholds ?? {
    monitor_at: 0.6,
    investigate_at: 0.85,
  };
  const flows =
    filtered?.flows.filter((f) =>
      `${f.flow_id} ${f.src_ip} ${f.dst_ip} ${f.protocol}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    ) ?? [];
  const anomalies =
    filtered?.anomalies.filter((e) => {
      const f = data?.flows.find((f) => f.flow_id === e.flow_id);
      return (
        (status === "all" || e.status === status) &&
        (priorityFilter === "all" ||
          priority(e.anomaly_score, thresholds) === priorityFilter) &&
        (!minScore || e.anomaly_score >= thresholds.investigate_at) &&
        anomalySearchText(e, f).toLowerCase().includes(query.toLowerCase())
      );
    }) ?? [];
  async function action(fn: () => Promise<void>, message: string) {
    busyRef.current = true;
    setBusy(true);
    try {
      await fn();
      setNotice(message);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }
  async function loadCase(i: Investigation, tab: CaseTab = "evidence") {
    const generation = ++caseGeneration.current;
    setInv(i);
    setCaseTab(tab);
    setPage("Cases");
    setSelectedEvent(null);
    setEv([]);
    setRep(null);
    setCaseLoading(true);
    try {
      const [e, r] = await Promise.all([
        api.evidence(i.investigation_id),
        api.report(i.investigation_id).catch((err) => {
          if (err.message === "report not found") return null;
          throw err;
        }),
      ]);
      if (generation !== caseGeneration.current) return;
      setEv(e);
      setRep(r);
    } catch (e) {
      if (generation === caseGeneration.current)
        setError(e instanceof Error ? e.message : "Unable to load case");
    } finally {
      if (generation === caseGeneration.current) setCaseLoading(false);
    }
  }
  function runInvestigation(e: Anomaly) {
    void action(
      async () => {
        const i = await api.investigate(e.event_id);
        const next = await api.snapshot();
        setData(next);
        await loadCase(i, "evidence");
      },
      "Investigation complete — opened in Cases",
    );
  }
  function reviewReport(s: string) {
    if (!rep) return;
    void action(async () => {
      setRep(await api.review(rep.report_id, s));
    }, `Report ${s}`);
  }
  function setEventStatus(s: string) {
    if (!selectedEvent) return;
    void action(async () => {
      await api.triage(selectedEvent.event_id, s);
      const next = {
        ...data!,
        anomalies: data!.anomalies.map((a) =>
          a.event_id === selectedEvent.event_id ? { ...a, status: s } : a,
        ),
      };
      setData(next);
      setSelectedEvent({ ...selectedEvent, status: s });
    }, "Event status updated");
  }
  async function selectEvent(e: Anomaly) {
    const generation = ++detailGeneration.current;
    setEventFlow(null);
    setSelectedEvent(e);
    const f = data?.flows.find((f) => f.flow_id === e.flow_id);
    if (f) return;
    try {
      const flow = await api.request<Flow>(
        `/flows/${encodeURIComponent(e.flow_id)}`,
      );
      if (generation === detailGeneration.current) setEventFlow(flow);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Flow unavailable");
    }
  }
  const selectedEventFlow =
    eventFlow ?? data?.flows.find((f) => f.flow_id === selectedEvent?.flow_id);
  const healthy = !!data && !offline;
  async function importFlowFile(file?: File) {
    if (!file) return;
    setImportBusy(true);
    setImportError("");
    setImportResult(null);
    try {
      const flows = await readFlowFile(file);
      const results: api.IngestResult[] = [];
      for (let i = 0; i < flows.length; i += 500) {
        results.push(...(await api.importFlows(flows.slice(i, i + 500))));
      }
      setImportResult({ filename: file.name, results });
      await refresh();
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Flow import failed");
    } finally {
      setImportBusy(false);
    }
  }
  return (
    <Tooltip.Provider delayDuration={250}>
      <div className="app-shell">
        {mobile && (
          <button
            className="mobile-scrim"
            aria-label="Close navigation"
            onClick={() => setMobile(false)}
          />
        )}
        <aside className={`sidebar ${mobile ? "visible" : ""}`}>
          <button
            className="brand"
            onClick={() => navigate("Overview")}
            aria-label="NetSentry Overview"
          >
            <span className="brand-mark">
              <Shield size={26} />
            </span>
            <span>
              NetSentry
              <small>Local</small>
            </span>
          </button>
          <div className="workspace-label">
            <span className="workspace-avatar">N</span>
            <div>
              Network workspace<small>Local environment</small>
            </div>
            <ChevronDown size={14} />
          </div>
          <nav>
            {nav.map((g) => (
              <div className="nav-group" key={g.group}>
                <span>{g.group}</span>
                {g.items.map(([name, Icon]) => (
                  <button
                    key={name}
                    className={page === name ? "active" : ""}
                    onClick={() => navigate(name)}
                  >
                    <Icon size={18} />
                    <span>{name}</span>
                    {name === "Anomalies" &&
                      !!data?.anomalies.filter((e) => e.status === "open")
                        .length && (
                        <b>
                          {
                            data.anomalies.filter((e) => e.status === "open")
                              .length
                          }
                        </b>
                      )}
                    {name === "Overview" && page === name && <i />}
                  </button>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="system-state">
              <span className={`status-dot ${healthy ? "" : "offline"}`} />
              {healthy ? "Backend connected" : "Backend unavailable"}
              <small>{data?.model.model_version ?? "No active model"}</small>
            </div>
          </div>
        </aside>
        <div className="main-shell">
          <header className="topbar">
            <div className="breadcrumb">
              <IconButton
                label="Open navigation"
                onClick={() => setMobile(true)}
              >
                <Menu size={18} />
              </IconButton>
              <span>NetSentry</span>
              <ChevronRight size={14} />
              <strong>{pageTitles[page] ?? page}</strong>
            </div>
            <div className="topbar-right">
              <IconButton
                label="Open anomaly queue"
                onClick={() => navigate("Anomalies")}
              >
                <Bell size={18} />
                {!!data?.anomalies.filter((a) => a.status === "open")
                  .length && <i className="notification-dot" />}
              </IconButton>
            </div>
          </header>
          <main>
            <div className="page-heading">
              <div>
                <div className="eyebrow">
                  NetSentry <span>/</span> {pageTitles[page] ?? page}
                </div>
                <h1>{pageTitles[page] ?? page}</h1>
                <p>{descriptions[page]}</p>
              </div>
              <div className="heading-actions">
                <label className="time-select">
                  <Activity size={15} />
                  <select
                    aria-label="Time range"
                    value={range}
                    onChange={(e) => {
                      setRange(e.target.value);
                      setFlowPage(0);
                    }}
                  >
                    <option value="24">Last 24 hours</option>
                    <option value="168">Last 7 days</option>
                    <option value="all">All loaded data</option>
                  </select>
                </label>
                <IconButton
                  label="Refresh data"
                  disabled={loading || busy}
                  onClick={() => void refresh()}
                >
                  <RefreshCw size={17} className={loading ? "spin" : ""} />
                </IconButton>
              </div>
            </div>
            {error && (
              <div className="error-banner" role="alert">
                <ShieldAlert size={18} />
                <span>
                  {error}
                  {!data && ". Start the backend."}
                </span>
                <button onClick={() => void refresh()}>Retry</button>
                <IconButton label="Dismiss error" onClick={() => setError("")}>
                  <X size={16} />
                </IconButton>
              </div>
            )}
            {data &&
              (data.flows.length >= 500 ||
                data.anomalies.length >= 500 ||
                data.investigations.length >= 500) && (
                <div className="notice-banner">
                  Loaded window capped at 500 records per feed. Counts reflect
                  this window.
                </div>
              )}
            {loading && !data ? (
              <Empty title="Connecting to NetSentry..." />
            ) : !filtered ? (
              <Empty title="Backend unavailable" text="No telemetry loaded." />
            ) : page === "Import" ? (
              <div className="flow-import-layout">
                <Panel title="Import flow records" meta="JSON · JSONL · 5,000 records max, 500 per request">
                  <div className="flow-upload">
                    <Upload size={22} />
                    <div>
                      <strong>Submit normalized records to the detector</strong>
                      <p>Use a JSON array or one JSON record per line. Required fields: src_ip, dst_ip, src_port, dst_port.</p>
                    </div>
                    <label className="flow-import-button">
                      {importBusy ? "Importing..." : "Choose file"}
                      <input type="file" accept=".json,.jsonl,.ndjson" disabled={importBusy} onChange={(e) => { void importFlowFile(e.target.files?.[0]); e.currentTarget.value = ""; }} />
                    </label>
                  </div>
                  {importError && <div className="error-banner" role="alert">{importError}</div>}
                  {importResult && <div className="import-result" role="status">
                    <strong>{importResult.filename}</strong>
                    <span>{importResult.results.length.toLocaleString()} flows scored</span>
                    <span>{importResult.results.filter((flow) => flow.event_id).length.toLocaleString()} anomaly events created</span>
                    {importResult.results.some((flow) => flow.event_id) && (
                      <div className="import-result-actions">
                        <button
                          className="button primary"
                          onClick={() => {
                            const eventId = importResult.results.find((flow) => flow.event_id)?.event_id;
                            const event = data?.anomalies.find((a) => a.event_id === eventId);
                            if (event) void selectEvent(event);
                            else navigate("Anomalies");
                          }}
                        >
                          View anomaly
                        </button>
                        <button className="button" onClick={() => navigate("Anomalies")}>
                          Open queue
                        </button>
                      </div>
                    )}
                  </div>}
                </Panel>
                <p className="flow-import-limitation">PCAP parsing and network-interface capture are not available. Flows lists telemetry already ingested by the API.</p>
              </div>
            ) : page === "Overview" ? (
              <Overview
                data={filtered}
                onNavigate={navigate}
                onSelect={(e) => void selectEvent(e)}
                onPriority={(p) => {
                  navigate("Anomalies");
                  setPriorityFilter(p);
                }}
              />
            ) : page === "Anomalies" ? (
              <>
                <div className="threshold-band">
                  <ShieldAlert size={22} />
                  <div>
                    <strong>Queue</strong>
                    <span>
                      Monitor at {thresholds.monitor_at.toFixed(2)} · investigate at {thresholds.investigate_at.toFixed(2)}.{" "}
                      <button className="text-link" onClick={() => navigate("Model")}>
                        How scoring works
                      </button>
                    </span>
                  </div>
                </div>
                <Panel
                  title="Anomaly queue"
                  meta={`${anomalies.length} events in this window`}
                  action={
                    <IconButton
                      label="Export filtered anomalies"
                      onClick={() =>
                        download("netsentry-anomalies.json", anomalies)
                      }
                    >
                      <Download size={17} />
                    </IconButton>
                  }
                >
                  <div className="filter-bar">
                    <div className="segmented">
                      {[
                        "all",
                        "open",
                        "monitoring",
                        "investigating",
                        "closed",
                      ].map((s) => (
                        <button
                          key={s}
                          className={status === s ? "selected" : ""}
                          onClick={() => setStatus(s)}
                        >
                          {human(s)}
                        </button>
                      ))}
                    </div>
                    <SearchBox value={query} onChange={setQuery} />
                  </div>
                  <label className="checkbox-label">
                    <select
                      aria-label="Detection priority"
                      className="priority-select"
                      value={priorityFilter}
                      onChange={(e) => setPriorityFilter(e.target.value)}
                    >
                      {["all", "critical", "high", "medium", "low"].map((p) => (
                        <option key={p} value={p}>
                          {p === "all" ? "All severity bands" : human(p)}
                        </option>
                      ))}
                    </select>
                    <input
                      type="checkbox"
                      checked={minScore}
                      onChange={(e) => setMinScore(e.target.checked)}
                    />
                    Score ≥ {thresholds.investigate_at.toFixed(2)}
                  </label>
                  <AnomalyTable
                    events={anomalies}
                    flows={data!.flows}
                    onSelect={(e) => void selectEvent(e)}
                    thresholds={thresholds}
                    empty={
                      <Empty
                        title="No anomalies yet"
                        text="Import sample_data/demo_flows.jsonl from Import."
                        action={
                          <button className="button primary" onClick={() => navigate("Import")}>
                            Go to Import
                          </button>
                        }
                      />
                    }
                  />
                </Panel>
              </>
            ) : page === "Flows" ? (
              <Panel
                title="Flow telemetry"
                meta={`${flows.length} matching flows`}
                action={
                  <IconButton
                    label="Export filtered flows"
                    onClick={() => download("netsentry-flows.json", flows)}
                  >
                    <Download size={17} />
                  </IconButton>
                }
              >
                <div className="filter-bar">
                  <SearchBox
                    value={query}
                    onChange={(s) => {
                      setQuery(s);
                      setFlowPage(0);
                    }}
                  />
                  <span className="muted">{flows.length} records</span>
                </div>
                {flows.length ? (
                  <>
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Flow ID</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Score</th>
                            <th>Decision</th>
                          </tr>
                        </thead>
                        <tbody>
                          {flows
                            .slice(flowPage * 15, (flowPage + 1) * 15)
                            .map((f) => (
                              <tr key={f.flow_id}>
                                <td className="mono">{time(f.timestamp)}</td>
                                <td>
                                  <button
                                    className="row-link"
                                    onClick={() => setSelectedFlow(f)}
                                  >
                                    {f.flow_id}
                                  </button>
                                </td>
                                <td className="mono">{f.src_ip}</td>
                                <td className="mono">
                                  {f.dst_ip}
                                  <small>Port {f.dst_port}</small>
                                </td>
                                <td>
                                  <span className="protocol">{f.protocol}</span>
                                </td>
                                <td className="mono">
                                  {f.anomaly_score.toFixed(2)}
                                </td>
                                <td>
                                  <Badge
                                    kind="decision"
                                    value={decisionFromScore(
                                      f.anomaly_score,
                                      thresholds,
                                    )}
                                  />
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="pagination">
                      <span>
                        {flowPage * 15 + 1}–
                        {Math.min(flows.length, (flowPage + 1) * 15)} of{" "}
                        {flows.length}
                      </span>
                      <IconButton
                        label="Previous page"
                        disabled={flowPage === 0}
                        onClick={() => setFlowPage((p) => p - 1)}
                      >
                        <ChevronLeft size={16} />
                      </IconButton>
                      <IconButton
                        label="Next page"
                        disabled={(flowPage + 1) * 15 >= flows.length}
                        onClick={() => setFlowPage((p) => p + 1)}
                      >
                        <ChevronRight size={16} />
                      </IconButton>
                    </div>
                  </>
                ) : (
                  <Empty
                    title="No flows yet"
                    text="Import sample_data/demo_flows.jsonl from Import."
                    action={
                      <button className="button primary" onClick={() => navigate("Import")}>
                        Go to Import
                      </button>
                    }
                  />
                )}
              </Panel>
            ) : page === "Cases" ? (
              inv ? (
                <>
                  <div className="case-toolbar">
                    <button
                      className="text-link"
                      onClick={() => {
                        setInv(null);
                        caseGeneration.current++;
                      }}
                    >
                      <ArrowLeft size={16} />
                      All cases
                    </button>
                    <div className="segmented">
                      {(["evidence", "report", "review"] as const).map((tab) => (
                        <button
                          key={tab}
                          className={caseTab === tab ? "selected" : ""}
                          onClick={() => setCaseTab(tab)}
                        >
                          {human(tab)}
                        </button>
                      ))}
                    </div>
                  </div>
                  <CaseView
                    inv={inv}
                    evidence={ev}
                    report={rep}
                    loading={caseLoading}
                    tab={caseTab}
                    onTab={setCaseTab}
                    onReview={reviewReport}
                    busy={busy}
                    event={data?.anomalies.find(
                      (e) => e.event_id === inv.event_id,
                    )}
                    flow={data?.flows.find(
                      (f) =>
                        f.flow_id ===
                        data.anomalies.find((e) => e.event_id === inv.event_id)
                          ?.flow_id,
                    )}
                    monitor={thresholds.monitor_at}
                    threshold={thresholds.investigate_at}
                  />
                </>
              ) : (
                <Panel
                  title="Cases"
                  meta={`${filtered.investigations.length} cases`}
                >
                  <div className="filter-bar">
                    <SearchBox
                      value={query}
                      onChange={setQuery}
                      placeholder="Search host, event, or case..."
                    />
                  </div>
                  {filtered.investigations.length ? (
                    <div className="case-list">
                      {filtered.investigations
                        .filter((i) => {
                          const event = data?.anomalies.find(
                            (e) => e.event_id === i.event_id,
                          );
                          const flow = data?.flows.find(
                            (f) => f.flow_id === event?.flow_id,
                          );
                          return `${i.investigation_id} ${i.event_id} ${flowHeadline(flow)}`
                            .toLowerCase()
                            .includes(query.toLowerCase());
                        })
                        .map((i) => {
                          const event = data?.anomalies.find(
                            (e) => e.event_id === i.event_id,
                          );
                          const flow = data?.flows.find(
                            (f) => f.flow_id === event?.flow_id,
                          );
                          const decision = event
                            ? decisionShort(
                                decisionFromScore(event.anomaly_score, thresholds),
                              )
                            : i.state;
                          return (
                          <button
                            className="case-row"
                            key={i.investigation_id}
                            onClick={() => void loadCase(i, "evidence")}
                          >
                            <span className="case-icon">
                              <Workflow size={21} />
                            </span>
                            <div>
                              <strong>{flowHeadline(flow)}</strong>
                              <small>
                                {caseSecondary(
                                  i.event_id,
                                  event?.anomaly_score,
                                  decision,
                                )}
                              </small>
                            </div>
                            <span className="muted">
                              {date(i.started_at).toLocaleDateString()} ·{" "}
                              {time(i.started_at)}
                            </span>
                            <Badge value={i.state} />
                            <ArrowRight size={17} />
                          </button>
                          );
                        })}
                    </div>
                  ) : (
                    <Empty
                      title="No cases yet"
                      text="Select an anomaly and choose Run investigation."
                      action={
                        <button className="button primary" onClick={() => navigate("Anomalies")}>
                          Open anomaly queue
                        </button>
                      }
                    />
                  )}
                </Panel>
              )
            ) : page === "Traffic Analytics" ? (
              <TrafficAnalytics
                data={filtered}
                onSource={(ip) => {
                  navigate("Flows");
                  setQuery(ip);
                }}
              />
            ) : page === "Model" ? (
              <ModelWorkbench model={data!.model} />
            ) : page === "Privacy Policy" ? (
              <PrivacyPolicy />
            ) : page === "API Health" ? (
              <div className="system-grid">
                <Panel title="Backend service">
                  <dl className="facts">
                    <div>
                      <dt>API status</dt>
                      <dd>
                        <Badge value={healthy ? "online" : "offline"} />
                      </dd>
                    </div>
                    <div>
                      <dt>Detector version</dt>
                      <dd>{data!.health.model}</dd>
                    </div>
                    <div>
                      <dt>LLM enhancement</dt>
                      <dd>
                        <Badge
                          value={
                            data!.health.llm_enabled ? "enabled" : "disabled"
                          }
                        />
                      </dd>
                    </div>
                    <div>
                      <dt>LLM model</dt>
                      <dd>{data!.health.llm_model}</dd>
                    </div>
                    <div>
                      <dt>Last response</dt>
                      <dd>{lastRefresh?.toLocaleTimeString()}</dd>
                    </div>
                  </dl>
                </Panel>
                <Panel title="Investigation services">
                  <dl className="facts">
                    <div>
                      <dt>Evidence collection</dt>
                      <dd>Read-only tools</dd>
                    </div>
                    <div>
                      <dt>Risk assessment</dt>
                      <dd>Deterministic</dd>
                    </div>
                    <div>
                      <dt>Reports</dt>
                      <dd>
                        {data!.health.llm_enabled
                          ? "LLM enhanced"
                          : "Rule-based synthesis"}
                      </dd>
                    </div>
                  </dl>
                </Panel>
              </div>
            ) : (
              <div className="system-grid">
                <Panel title="Workspace preferences">
                  <div className="setting-row">
                    <div>
                      <strong>Automatic refresh</strong>
                      <small>15 seconds</small>
                    </div>
                    <input
                      aria-label="Automatic refresh"
                      role="switch"
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                    />
                  </div>
                </Panel>
              </div>
            )}
          </main>
        </div>
        <Drawer
          open={!!selectedFlow || !!selectedEvent}
          onClose={() => {
            setSelectedFlow(null);
            setSelectedEvent(null);
          }}
          title={flowHeadline(selectedFlow ?? selectedEventFlow)}
          description={
            selectedEvent
              ? caseSecondary(
                  selectedEvent.event_id,
                  selectedEvent.anomaly_score,
                  decisionShort(
                    decisionFromScore(selectedEvent.anomaly_score, thresholds),
                  ),
                )
              : selectedFlow
                ? caseSecondary(
                    selectedFlow.flow_id,
                    selectedFlow.anomaly_score,
                    decisionShort(
                      decisionFromScore(selectedFlow.anomaly_score, thresholds),
                    ),
                  )
                : "Network flow details"
          }
        >
          {(selectedFlow || selectedEventFlow) && (
            <>
              <dl className="facts">
                <div>
                  <dt>Source</dt>
                  <dd className="mono">
                    {(selectedFlow ?? selectedEventFlow)!.src_ip}
                  </dd>
                </div>
                <div>
                  <dt>Destination</dt>
                  <dd className="mono">
                    {(selectedFlow ?? selectedEventFlow)!.dst_ip}
                  </dd>
                </div>
                <div>
                  <dt>Port / protocol</dt>
                  <dd>
                    {(selectedFlow ?? selectedEventFlow)!.dst_port} /{" "}
                    {(selectedFlow ?? selectedEventFlow)!.protocol}
                  </dd>
                </div>
                <div>
                  <dt>Flow</dt>
                  <dd className="mono">
                    {(selectedFlow ?? selectedEventFlow)!.flow_id}
                  </dd>
                </div>
              </dl>
              <ScoreGauge
                score={
                  selectedEvent?.anomaly_score ?? selectedFlow!.anomaly_score
                }
                monitor={thresholds.monitor_at}
                investigate={thresholds.investigate_at}
              />
              <h3 className="detail-heading">Observed features</h3>
              <dl className="facts feature-facts">
                {Object.entries(
                  (selectedFlow ?? selectedEventFlow)!.features,
                ).map(([k, v]) => (
                  <div key={k}>
                    <dt>{featureName(k)}</dt>
                    <dd>{featureValue(k, v)}</dd>
                  </div>
                ))}
              </dl>
            </>
          )}
          {selectedEvent && (
            <div className="drawer-actions">
              <label>
                Event status
                <select
                  aria-label="Event status"
                  value={selectedEvent.status}
                  disabled={busy}
                  onChange={(e) => setEventStatus(e.target.value)}
                >
                  {["open", "monitoring", "investigating", "closed"].map(
                    (s) => (
                      <option key={s} value={s}>
                        {human(s)}
                      </option>
                    ),
                  )}
                </select>
              </label>
              <button
                className="button primary"
                disabled={busy}
                onClick={() => runInvestigation(selectedEvent)}
              >
                {busy ? (
                  <LoaderCircle size={17} className="spin" />
                ) : (
                  <Workflow size={17} />
                )}
                Run investigation
                <ArrowRight size={16} />
              </button>
            </div>
          )}
          {selectedFlow &&
            data?.anomalies.find((a) => a.flow_id === selectedFlow.flow_id) && (
              <div className="drawer-actions">
                <button
                  className="button primary"
                  onClick={() => {
                    const event = data.anomalies.find(
                      (a) => a.flow_id === selectedFlow.flow_id,
                    )!;
                    setSelectedFlow(null);
                    void selectEvent(event);
                  }}
                >
                  <ShieldAlert size={17} />
                  View anomaly
                  <ArrowRight size={16} />
                </button>
              </div>
            )}
        </Drawer>
        {notice && (
          <div className="toast" role="status">
            <Check size={17} />
            {notice}
          </div>
        )}
      </div>
    </Tooltip.Provider>
  );
}

function PrivacyPolicy() {
  return (
    <div className="privacy-page">
      <Panel title="Privacy policy" meta="For the current self-hosted console">
        <div className="privacy-copy">
          <section>
            <h3>Browser and API</h3>
            <p>
              The console sends requests to the NetSentry API at the same origin.
              It does not include analytics, advertising, or tracking scripts,
              and it does not save telemetry in browser storage.
            </p>
          </section>
          <section>
            <h3>Network and investigation data</h3>
            <p>
              Flow records, anomaly events, evidence, and reports are handled
              by the backend
              configured for this installation. The deployment operator
              controls its database, access, and retention.               An optional language-model provider configured on the backend
              may receive investigation data to generate report text.
            </p>
          </section>
          <section>
            <h3>Data exports</h3>
            <p>
              JSON exports are created only when an analyst requests a
              download. Imported flow records are submitted to the configured
              backend for scoring and storage.
            </p>
          </section>
          <section>
            <h3>Deployment scope</h3>
            <p>
              NetSentry is self-hosted software, not a centrally operated web
              service. The organization operating an installation is responsible
              for its deployment-specific privacy notice and legal obligations.
              This page describes the current console behavior and should be
              reviewed before exposing an installation publicly.
            </p>
          </section>
        </div>
      </Panel>
    </div>
  );
}
