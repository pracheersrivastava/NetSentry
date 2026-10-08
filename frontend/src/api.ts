import type { Snapshot, Investigation, Evidence, Report } from "./types";

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
