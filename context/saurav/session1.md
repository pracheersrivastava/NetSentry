# NetSentry — Session 1 handoff (backend → ML teammate)

Date: 2026-10-07 · Branch: `saurav` @ `8fd0673` · Base: `main` (README-only) + `aryan` notebook branch
Owner of this doc: Saurav (backend). Reader: ML teammate (model training + artifact drop).

Backend is **complete and swap-safe**. Only the real `.joblib` is missing.
This doc is everything ML needs to train, validate, and ship without breaking backend/dashboard.

---

## 1. Decisions you inherit (do not relitigate)

- **Option A (in-process model).** API loads the model file at startup (`ml/predict.py:14`).
  No separate ML microservice. Dashboard never touches the model — only `GET /flows`,
  `GET /anomalies`, `POST /model/predict` (`api/main.py:78-201`).
- **Script replay, not live NIC.** Demo uses `sample_data/demo_flows.jsonl` →
  `POST /flows/ingest` or `POST /flows/batch`. Live sniffing later posts to the same
  batch endpoint; backend won't change.
- **Stub today, joblib tomorrow, zero API change.** `ml/interface.py:11`
  `BaseDetector.predict(features) -> {anomaly_score 0-1, prediction, model, model_version}`.
  `StubDetector` (`ml/stub.py:9`, `v0-stub`) implements it with a volume heuristic.
  Your `SklearnDetector` (`ml/real.py:9`) implements the same interface.

## 2. Frozen contracts (do NOT rename/reorder without backend)

| Contract | File | Rule |
|---|---|---|
| Feature order (12, exact) | `features/schema.json:2` | Model consumes vector in this order. Bumping = bump `model_version` + schema version together |
| Flow input | `api/schemas.py:6` `FlowIn` | `src/dst_ip, src/dst_port, protocol, duration, orig/resp_bytes, orig/resp_pkts` |
| Predict output | `api/schemas.py:21` `PredictOut` | `{flow_id, model, model_version, anomaly_score 0-1, prediction, features_used}` |
| Thresholds | `configs/threshold.yaml:1` | `>=0.85 open (investigate)`, `>=0.60 monitoring`, else store-only. Score scale is 0-1, not raw IsolationForest negative scores |
| DB tables | `database/models.py:18` | 7 tables: `network_flows, anomaly_events, investigations, evidence, tool_calls, reports, model_versions` |

Feature order (copy-paste for training):
`duration, orig_bytes, resp_bytes, total_bytes, orig_pkts, resp_pkts, bytes_per_sec, pkts_per_sec, dst_port, protocol_TCP, unique_dst_ports_5min, failed_conn_ratio_5min`

Derived the same way every time in `features/flow_features.py:11`
(`total_bytes = orig+resp`, `bytes_per_sec = total/max(duration,0.001)`, `protocol_TCP = 1 if TCP else 0`;
behavioral `unique_dst_ports_5min / failed_conn_ratio_5min` default `1 / 0.0` until live aggregator exists).

## 3. What you must deliver (one file)

`ml/models/isolation_forest_v1.joblib` as a **dict**:
```python
{"model": IsolationForest(...), "scaler": StandardScaler(...),
 "feature_order": [...12 names above, same order...], "version": "v1.0"}
```
- Train primarily on benign traffic (Report §10.2), calibrate threshold on validation —
  do NOT hardcode 0.85 inside the model; backend maps your normalized 0-1 score via `threshold.yaml`.
- Bare-sklearn-model artifact also loads, but dict form is required for reproducibility
  (scaler + order travel with the model).
- `version` string is logged per event (`anomaly_events.model_version`) and in
  `model_versions` at startup (`api/main.py:37`) — old `v0-stub` events stay queryable after swap.

Train/eval data: CIC-IDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 (Report Table 4) + controlled
lab bursts (high conn rate, port diversity, failed-ratio). Report precision/recall/F1,
ROC-AUC, FPR — FPR matters most for SOC trust.

## 4. How to ship without breaking anything

```bash
cp configs/.env.example .env            # set DATABASE_URL, MODEL_PATH, LLM_* (all ignored by git)
# train -> save dict artifact to ml/models/isolation_forest_v1.joblib
python -m pytest tests/ -q              # 9 tests must stay green
# start backend, then WITHOUT restarting:
curl -X POST http://localhost:8000/model/validate   # {"ok":true, "dummy_score":...} or {"ok":false,"error":...}
# if ok: set MODEL_PATH in .env, restart uvicorn, check:
curl http://localhost:8000/health       # {"model":"v1.0",...}
curl http://localhost:8000/model/info   # shows live version + expected feature_order
```

Swap guarantees built for you:
- `ml/validate.py:11` rejects bad artifacts (order mismatch, missing scaler transform,
  broken predict) → factory falls back to stub with `[ml] WARN`, never 500.
- `ml/real.py:22` normalizes `decision_function` (`0.5 - raw` clamped 0-1),
  handles `-1/1` classifiers, degrades to `0.5` instead of crashing ingest.
- Dedupe: re-ingesting same `flow_id` reuses `ANM-xxx` (`database/repository.py:113`);
  re-POST same event reuses `INV-xxx`. Safe to replay.

## 5. Current backend surface (for orientation, not your TODO)

- `POST /flows/ingest`, `POST /flows/batch` (500 cap, single commit — live path)
- `GET /flows`, `GET /flows/{id}`, `GET /anomalies?status=&min_score=`, `PATCH /anomalies/{id}`
- `POST /model/predict` (manual scoring), `GET /model/info`, `POST /model/validate`
- `POST /investigations/{event_id}` (stub runs 3 deterministic tools:
  `get_network_event, search_historical_traffic, analyze_connections` in
  `agent/tools/deterministic.py:20`, stores `evidence` + `tool_calls`),
  `GET /investigations`, `GET /investigations/{id}/evidence`,
  `GET /reports/{id}`, `POST /reports/{id}/review`
- Reports: `reports/generator.py:14` builds JSON-first incident report
  (`incident_id, severity, observed_facts[], findings[], confidence, tool_trace[]`);
  Gemini synthesis (`llm/synthesizer.py:20`) enhances findings only on success
  (`LLM_ENABLED=true` + `GEMINI_API_KEY`), stub kept on 429/off. Quota: flash-lite ~500 rpd.
- Dashboard: `dashboard/app.py` (Live / Anomalies / Investigations), Streamlit + custom CSS.
- Scale: Postgres-ready (`DATABASE_URL=postgresql+psycopg://...`, pool 5+10 in
  `database/db.py:14`; compose `pg` profile in `docker/docker-compose.yml:18`);
  query indexes on timestamp/status/scores/FKs (`database/models.py`);
  `docker/Dockerfile` single-image demo.
- Demo reset: `python scripts/seed.py` → 3 flows (0.6 monitor / 0.85 anomaly / 0.1 normal),
  then `uvicorn api.main:app --port 8000`, `streamlit run dashboard/app.py`.
  Full 3-min script in `README.md:335`.

## 6. Your checklist

- [ ] Fix 12-feature pipeline to match `features/schema.json` order exactly
- [ ] Train IsolationForest (+ scaler), save dict artifact with `version`
- [ ] `POST /model/validate` → `ok:true`
- [ ] Restart, verify `/health` = your version, spot-check `POST /model/predict` on
      `sample_data/benign.json` (expect low) vs `burst.json` (expect ≥0.85)
- [ ] Send metrics (precision/recall/F1/ROC-AUC/FPR) + training-data description for
      `model_versions` row and final report
- [ ] Do NOT touch `api/schemas.py`, `features/schema.json`, `configs/threshold.yaml`
      without a backend PR — they are cross-team contracts

Questions for Saurav: threshold recalibration values after your validation set,
and whether behavioral windows (`unique_dst_ports_5min`) should be computed
server-side before you finalize features.
