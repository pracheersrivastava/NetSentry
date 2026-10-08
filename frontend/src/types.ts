export type Features = Record<string, number>;
export type Flow = {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  features: Features;
  anomaly_score: number;
};
export type Anomaly = {
  event_id: string;
  flow_id: string;
  anomaly_score: number;
  model_version: string;
  status: string;
  created_at: string;
};
export type Investigation = {
  investigation_id: string;
  event_id: string;
  state: string;
  started_at: string;
  completed_at: string | null;
  outcome: string | null;
};
export type Evidence = {
  evidence_id: string;
  investigation_id: string;
  source_tool: string;
  evidence_type: string;
  payload: Record<string, unknown>;
  timestamp: string;
};
export type Hypothesis = {
  hypothesis: string;
  status: string;
  confidence?: number;
  evidence_summary?: string;
};
export type Report = {
  report_id: string;
  investigation_id: string;
  generated_at: string;
  reviewer_status: string;
  report_json: {
    severity: string;
    confidence: number;
    findings: string[];
    observed_facts: string[];
    hypotheses: Hypothesis[];
    uncertainties: string[];
    recommended_next_steps: string[];
    tool_trace: string[];
    mitre_techniques?: { id: string; name: string; tactic: string }[];
    risk_assessment?: {
      level?: string;
      composite_score?: number;
      rationale?: string;
      factor_breakdown?: {
        signal: string;
        contribution: number;
        flagged: boolean;
      }[];
    };
  };
};
export type Model = {
  model: string;
  model_version: string;
  feature_order: string[];
  artifact: string;
  thresholds: { monitor_at: number; investigate_at: number };
};
export type Prediction = {
  flow_id: string;
  model: string;
  model_version: string;
  anomaly_score: number;
  prediction: string;
  features_used: Features;
};
export type ModelMetrics = {
  available: boolean;
  dataset?: string;
  training_type?: string;
  training_samples?: number;
  benign_validation_samples?: number;
  roc_auc?: number;
  precision?: number;
  recall?: number;
  f1?: number;
  false_positive_rate?: number;
};
export type Health = {
  status: string;
  model: string;
  llm_enabled: boolean;
  llm_model: string;
};
export type Snapshot = {
  flows: Flow[];
  anomalies: Anomaly[];
  investigations: Investigation[];
  model: Model;
  health: Health;
};
