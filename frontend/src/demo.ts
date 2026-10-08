import type {
  Snapshot,
  Evidence,
  Report,
  Anomaly,
  Investigation,
} from "./types";

export function createDemo(): Snapshot {
  const now = Date.now();
  const flagged = new Map([
    [0, 0.94], [1, 0.89], [2, 0.71], [7, 0.67], [8, 0.91], [15, 0.88],
    [27, 0.64], [28, 0.97], [35, 0.73], [49, 0.86], [50, 0.92], [51, 0.69],
    [68, 0.87], [71, 0.95], [72, 0.62], [83, 0.9], [91, 0.78], [92, 0.89],
  ]);
  let elapsedMinutes = 0;
  const flows = Array.from({ length: 96 }, (_, i) => {
    if (i > 0) elapsedMinutes += 2 + ((i * 73) % 17);
    const score = flagged.get(i) ?? 0.03 + ((i * 29) % 52) / 100;
    return {
      flow_id: `FLOW-${(0xc820 + i).toString(16).toUpperCase()}`,
      timestamp: new Date(now - elapsedMinutes * 60000).toISOString(),
      src_ip: `192.168.1.${[18, 12, 42, 10, 25, 31][i % 6]}`,
      dst_ip: `10.0.0.${[91, 25, 42, 18][i % 4]}`,
      src_port: 44001 + i,
      dst_port: [443, 22, 8080, 53, 80, 443][i % 6],
      protocol: i % 6 === 3 ? "UDP" : "TCP",
      anomaly_score: score,
      features: {
        duration: score > 0.85 ? 0.42 : 2.8,
        total_bytes: score > 0.85 ? 82400 : 5100,
        orig_pkts: score > 0.85 ? 179 : 10,
        resp_pkts: score > 0.85 ? 5 : 10,
        orig_bytes: score > 0.85 ? 80400 : 2100,
        resp_bytes: score > 0.85 ? 2000 : 3000,
        dst_port: [443, 22, 8080, 53, 80, 443][i % 6],
        protocol_TCP: i % 6 === 3 ? 0 : 1,
        bytes_per_sec: score > 0.85 ? 196190 : 1821,
        pkts_per_sec: score > 0.85 ? 438 : 7,
        unique_dst_ports_5min: score > 0.85 ? 27 : 1,
        failed_conn_ratio_5min: score > 0.85 ? 0.51 : 0.02,
      },
    };
  });
  const anomalies = flows
    .filter((f) => f.anomaly_score >= 0.6)
    .map((f, i) => ({
      event_id: `ANM-${(0x91f2 + i).toString(16).toUpperCase()}`,
      flow_id: f.flow_id,
      anomaly_score: f.anomaly_score,
      model_version: "v1.0-demo",
      status:
        i % 7 === 6 ? "closed" : f.anomaly_score < 0.85 ? "monitoring" : "open",
      created_at: f.timestamp,
    }));
  const investigations = anomalies
    .filter((a) => a.anomaly_score >= 0.85)
    .slice(1, 5)
    .map((a, i) => ({
      investigation_id: `INV-${(0x7f2a + i).toString(16).toUpperCase()}`,
      event_id: a.event_id,
      state: "done",
      started_at: a.created_at,
      completed_at: new Date(
        new Date(a.created_at).getTime() + 4200,
      ).toISOString(),
      outcome: "Demo investigation complete",
    }));
  return {
    flows,
    anomalies,
    investigations,
    health: {
      status: "ok",
      model: "v1.0-demo",
      llm_enabled: false,
      llm_model: "Demo",
    },
    model: {
      model: "isolation_forest",
      model_version: "v1.0-demo",
      artifact: "Demo dataset",
      feature_order: Object.keys(flows[0].features),
      thresholds: { monitor_at: 0.6, investigate_at: 0.85 },
    },
  };
}
export function demoEvidence(inv: Investigation, data?: Snapshot): Evidence[] {
  const event = data?.anomalies.find((a) => a.event_id === inv.event_id);
  const flow = data?.flows.find((f) => f.flow_id === event?.flow_id);
  return [
    [
      "get_network_event",
      {
        event_id: inv.event_id,
        anomaly_score: event?.anomaly_score ?? 0.89,
        flow,
      },
    ],
    [
      "feature_attribution",
      {
        attributions: [
          {
            feature: "bytes_per_sec",
            value: flow?.features.bytes_per_sec ?? 196190,
            signal: "High bandwidth throughput anomaly",
            severity: "high",
            threshold: 20000,
          },
          {
            feature: "pkts_per_sec",
            value: flow?.features.pkts_per_sec ?? 438,
            signal: "High packet rate burst",
            severity: "high",
            threshold: 20,
          },
          {
            feature: "unique_dst_ports_5min",
            value: flow?.features.unique_dst_ports_5min ?? 27,
            signal: "Horizontal port diversity sweep",
            severity: "critical",
            threshold: 9,
          },
        ].filter((a) => a.value > a.threshold),
      },
    ],
    [
      "analyze_connections",
      {
        src_ip: flow?.src_ip ?? "192.168.1.18",
        flow_count: 27,
        unique_dst_ports: 27,
        scan_like: true,
        total_bytes: 82400,
      },
    ],
    [
      "search_historical_traffic",
      { past_flow_count: 2, baseline_bytes_per_sec: 1821 },
    ],
    [
      "analyze_destination",
      {
        dst_ip: flow?.dst_ip ?? "10.0.0.91",
        known_service: flow?.dst_port === 22 ? "SSH" : "HTTPS",
        primary_port: flow?.dst_port ?? 443,
        high_value_target: false,
      },
    ],
    [
      "hypothesis_validator",
      {
        hypotheses: [
          {
            hypothesis: "network_reconnaissance_port_scan",
            status: "confirmed",
            confidence: 0.9,
            evidence_summary:
              "27 destination ports observed in connection telemetry.",
          },
        ],
      },
    ],
    [
      "risk_assessor",
      {
        level: "high",
        composite_score: 0.79,
        confidence: 0.85,
        rationale:
          "Elevated score, port diversity, and limited source history.",
      },
    ],
  ].map(([tool, payload], i) => ({
    evidence_id: `EV-DEMO-${i}`,
    investigation_id: inv.investigation_id,
    source_tool: tool as string,
    evidence_type: "demo",
    payload: payload as Record<string, unknown>,
    timestamp: inv.started_at,
  }));
}
export function demoReport(inv: Investigation, event?: Anomaly): Report {
  return {
    report_id: `RPT-${inv.investigation_id.slice(4)}`,
    investigation_id: inv.investigation_id,
    generated_at: inv.completed_at ?? inv.started_at,
    reviewer_status: "pending",
    report_json: {
      severity:
        (event?.anomaly_score ?? 0.89) >= 0.9
          ? "critical"
          : (event?.anomaly_score ?? 0.89) >= 0.85
            ? "high"
            : "medium",
      confidence: 0.85,
      findings: [
        "Connection diversity and an elevated packet rate suggest network reconnaissance. The activity warrants analyst review; telemetry alone does not establish malicious intent.",
      ],
      observed_facts: [
        `${event?.flow_id ?? "Flow"} scored ${(event?.anomaly_score ?? 0.89).toFixed(2)}.`,
        "27 unique destination ports observed.",
        "Source has only 2 historical flows.",
      ],
      hypotheses: [
        {
          hypothesis: "network_reconnaissance_port_scan",
          status: "confirmed",
          confidence: 0.9,
          evidence_summary:
            "27 destination ports observed in connection telemetry.",
        },
      ],
      uncertainties: [
        "Sample data only.",
        "Encrypted payloads were not inspected.",
      ],
      recommended_next_steps: [
        "Verify destination host logs.",
        "Validate the source asset owner.",
        "Check for active egress.",
      ],
      tool_trace: demoEvidence(inv).map((e) => e.source_tool),
      mitre_techniques: [
        {
          id: "T1046",
          name: "Network Service Discovery",
          tactic: "Reconnaissance",
        },
      ],
      risk_assessment: {
        level: "high",
        composite_score: 0.79,
        rationale:
          "Elevated anomaly score, port diversity, and limited source history.",
        factor_breakdown: [
          { signal: "ml_anomaly", contribution: 0.44, flagged: true },
          { signal: "port_diversity", contribution: 0.2, flagged: true },
          { signal: "historical_novelty", contribution: 0.15, flagged: true },
        ],
      },
    },
  };
}
