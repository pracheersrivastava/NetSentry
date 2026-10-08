import type {
  Snapshot,
  Investigation,
  Evidence,
  Report,
  ModelMetrics,
  Prediction,
} from "./types";

export async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    signal:
      options?.signal ??
      AbortSignal.timeout(options?.method === "POST" ? 90000 : 10000),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(
      typeof body.detail === "string"
        ? body.detail
        : `Request failed (${response.status})`,
    );
  }
  return response.json();
}
export async function snapshot(): Promise<Snapshot> {
  const [flows, anomalies, investigations, model, health] = await Promise.all([
    request<Snapshot["flows"]>("/flows?limit=500"),
    request<Snapshot["anomalies"]>("/anomalies?limit=500"),
    request<Snapshot["investigations"]>("/investigations?limit=500"),
    request<Snapshot["model"]>("/model/info"),
    request<Snapshot["health"]>("/health"),
  ]);
  return { flows, anomalies, investigations, model, health };
}
export type FlowImport = {
  flow_id?: string;
  timestamp?: string | null;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol?: string;
  duration?: number;
  orig_bytes?: number;
  resp_bytes?: number;
  orig_pkts?: number;
  resp_pkts?: number;
};
export type IngestResult = {
  flow_id: string;
  anomaly_score: number;
  prediction: string;
  event_id: string | null;
};
export const importFlows = (flows: FlowImport[]) =>
  request<IngestResult[]>("/flows/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(flows),
  });
export const investigate = (id: string) =>
  request<Investigation>(`/investigations/${encodeURIComponent(id)}`, {
    method: "POST",
  });
export const evidence = (id: string) =>
  request<Evidence[]>(`/investigations/${encodeURIComponent(id)}/evidence`);
export const report = (id: string) =>
  request<Report>(`/reports/${encodeURIComponent(id)}`);
export const triage = (id: string, status: string) =>
  request(
    `/anomalies/${encodeURIComponent(id)}?status=${encodeURIComponent(status)}`,
    { method: "PATCH" },
  );
export const review = (id: string, status: string) =>
  request<Report>(
    `/reports/${encodeURIComponent(id)}/review?status=${status}`,
    { method: "POST" },
  );
export const predict = (flow: FlowImport) =>
  request<Prediction>("/model/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(flow),
  });
export const modelMetrics = () => request<ModelMetrics>("/model/metrics");
