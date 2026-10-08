import type { Anomaly, Flow } from "./types";

export type Decision = "store" | "monitor" | "investigate";
export type Thresholds = { monitor_at: number; investigate_at: number };

export const SCORE_HINT =
  "Isolation Forest anomaly score; not a probability.";

export const SCORING_HELP = {
  title: "How scoring works",
  body: "Each ingested flow is scored by Isolation Forest from 0 to 1. The score is not a probability of attack. Thresholds decide what happens next: below monitor the flow is stored only, between monitor and investigate it is queued for watching, and at or above investigate an anomaly event is opened for triage.",
};

export function decisionFromScore(
  score: number,
  thresholds: Thresholds,
): Decision {
  if (score >= thresholds.investigate_at) return "investigate";
  if (score >= thresholds.monitor_at) return "monitor";
  return "store";
}

export function decisionLabel(score: number, thresholds: Thresholds): string {
  const band = decisionFromScore(score, thresholds);
  if (band === "store") return "Below threshold — stored only";
  if (band === "monitor") return "Monitor";
  return "Investigate";
}

export function decisionShort(band: Decision | string): string {
  const value = band === "normal" || band === "stored" ? "store" : band === "monitoring" ? "monitor" : band;
  if (value === "store") return "Stored only";
  if (value === "monitor") return "Monitor";
  if (value === "investigate") return "Investigate";
  return value;
}

export function severityLabel(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

export function toolLabel(sourceTool: string): string {
  return (
    {
      get_network_event: "Triggering flow",
      lookup_dns: "DNS lookup for destination",
      lookup_reputation: "IP reputation",
      analyze_destination: "Destination analysis",
      analyze_connections: "Connection analysis",
      search_historical_traffic: "Historical traffic search",
      search_similar_incidents: "Similar incidents",
      feature_attribution: "Feature analysis",
      hypothesis_validator: "Hypothesis checks",
      risk_assessor: "Risk assessment",
    }[sourceTool] ?? sourceTool.replaceAll("_", " ")
  );
}

export function payloadKeyLabel(key: string): string {
  return (
    {
      hostname: "Hostname",
      resolved: "Resolved",
      reputation: "Reputation",
      category: "Category",
      similar_count: "Similar cases",
      match_count: "Matches",
      dst_ip: "Destination",
      src_ip: "Source",
      port: "Port",
      protocol: "Protocol",
      service: "Service",
      flagged: "Flagged",
    }[key] ?? key.replaceAll("_", " ")
  );
}

export function flowHeadline(flow?: Flow | null): string {
  if (!flow) return "Flow details unavailable";
  return `${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port} (${flow.protocol})`;
}

export function caseSecondary(
  eventId: string,
  score: number | undefined,
  decision: string,
): string {
  const scoreText = score == null ? "score unavailable" : `score ${score.toFixed(2)}`;
  return `${eventId} · ${scoreText} · ${decision}`;
}

export function anomalySearchText(event: Anomaly, flow?: Flow): string {
  return `${event.event_id} ${event.flow_id} ${flow?.src_ip ?? ""} ${flow?.dst_ip ?? ""}`;
}
