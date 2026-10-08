import { useEffect, useState } from "react";
import { LoaderCircle, Play } from "lucide-react";
import * as api from "./api";
import type { Model, ModelMetrics, Prediction } from "./types";
import { Badge, Panel, ScoreGauge, featureName, featureValue, human } from "./components";
import { SCORING_HELP } from "./copy";

const sampleFlow = {
  flow_id: "FLOW-TEST",
  src_ip: "192.168.1.18",
  dst_ip: "10.0.0.25",
  src_port: 49152,
  dst_port: 443,
  protocol: "TCP",
  duration: 1.2,
  orig_bytes: 1200,
  resp_bytes: 800,
  orig_pkts: 12,
  resp_pkts: 8,
};

function metric(value?: number, percent = false) {
  if (value === undefined) return "—";
  return percent ? `${(value * 100).toFixed(2)}%` : value.toFixed(3);
}

export default function ModelWorkbench({ model }: { model: Model }) {
  const [input, setInput] = useState(JSON.stringify(sampleFlow, null, 2));
  const [prediction, setPrediction] = useState<Prediction | null>(null);
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [error, setError] = useState("");
  const [scoring, setScoring] = useState(false);

  useEffect(() => {
    void api.modelMetrics().then(setMetrics).catch(() => setMetrics({ available: false }));
  }, []);

  async function score() {
    setError("");
    try {
      const flow = JSON.parse(input) as api.FlowImport;
      for (const key of ["src_ip", "dst_ip", "src_port", "dst_port"] as const) {
        if (flow[key] === undefined || flow[key] === "") throw new Error(`Test flow needs ${key}`);
      }
      setScoring(true);
      setPrediction(await api.predict(flow));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to score test flow");
    } finally {
      setScoring(false);
    }
  }

  return (
    <div className="model-workbench">
      <div className="system-grid">
        <Panel title="Active detector" meta={human(model.model)}>
          <dl className="facts">
            <div><dt>Version</dt><dd>{model.model_version}</dd></div>
            <div><dt>Mode</dt><dd>{model.model_version.includes("stub") ? "Heuristic fallback" : "Model artifact"}</dd></div>
            <div><dt>Artifact</dt><dd className="artifact-path">{model.artifact || "Not configured"}</dd></div>
            <div><dt>Monitor boundary</dt><dd>{model.thresholds.monitor_at.toFixed(2)}</dd></div>
            <div><dt>Investigate boundary</dt><dd>{model.thresholds.investigate_at.toFixed(2)}</dd></div>
          </dl>
          <details className="how-scoring">
            <summary>{SCORING_HELP.title}</summary>
            <p>{SCORING_HELP.body}</p>
            <p>
              Below {model.thresholds.monitor_at.toFixed(2)} the flow is stored only.
              From {model.thresholds.monitor_at.toFixed(2)} to {model.thresholds.investigate_at.toFixed(2)} it is monitored.
              At or above {model.thresholds.investigate_at.toFixed(2)} an anomaly event is created for triage.
              UI severity (critical / high / medium / low) is a display band on the same score; it can differ from the store / monitor / investigate decision.
            </p>
            <p>Normalized flow → 12 features → {human(model.model)} → threshold decision → anomaly event</p>
          </details>
        </Panel>
        <Panel title="Feature contract" meta={`${model.feature_order.length} model inputs`}>
          <div className="feature-list">
            {model.feature_order.map((feature, index) => (
              <div key={feature}><span>{String(index + 1).padStart(2, "0")}</span><code>{feature}</code></div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Test a flow" meta="Scores a flow without storing it">
        <label className="model-input-label" htmlFor="test-flow">Normalized flow JSON</label>
        <textarea id="test-flow" className="model-input" value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} />
        <button className="button primary" onClick={() => void score()} disabled={scoring}>
          {scoring ? <LoaderCircle className="spin" size={16} /> : <Play size={16} />} Score flow
        </button>
        {prediction && (
          <div className="prediction-result">
            <div><span>Prediction</span><Badge value={prediction.prediction} /></div>
            <ScoreGauge score={prediction.anomaly_score} monitor={model.thresholds.monitor_at} investigate={model.thresholds.investigate_at} />
            <small>{human(prediction.model)} · {prediction.model_version} · {prediction.flow_id}</small>
            <details><summary>Features used</summary><div className="used-features">{Object.entries(prediction.features_used).map(([key, value]) => <span key={key}>{featureName(key)} <strong>{featureValue(key, value)}</strong></span>)}</div></details>
          </div>
        )}
      </Panel>

      <Panel title="Evaluation snapshot" meta={metrics?.available ? `${metrics.dataset} · ${metrics.training_type?.replaceAll("_", " ")}` : "Evaluation data unavailable"}>
        {metrics?.available ? <div className="metric-grid">
          <div><span>ROC-AUC</span><strong>{metric(metrics.roc_auc)}</strong></div>
          <div><span>False-positive rate</span><strong>{metric(metrics.false_positive_rate, true)}</strong></div>
          <div><span>Training samples</span><strong>{metrics.training_samples?.toLocaleString() ?? "—"}</strong></div>
          <div><span>Benign validation</span><strong>{metrics.benign_validation_samples?.toLocaleString() ?? "—"}</strong></div>
        </div> : <div className="model-placeholder"><p>No bundled evaluation report is available for the active artifact.</p></div>}
      </Panel>
      {error && <div className="error-banner" role="alert">{error}</div>}
    </div>
  );
}
