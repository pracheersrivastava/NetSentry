# NetSentry AI

NetSentry scores normalized network flow records, stores anomaly events, and lets an analyst start an evidence-grounded investigation. The React console presents the records, model thresholds, investigations, and reports returned by the configured FastAPI backend.

## What Works Today

- Flow scoring and storage through `POST /flows/ingest` or `POST /flows/batch`.
- Anomaly events based on the configured monitor and investigate thresholds. The current defaults are `0.60` and `0.85`.
- Flow and anomaly listing, detail views, and analyst status updates.
- Analyst-triggered LangGraph investigation, evidence collection, risk assessment, and report generation.
- Model metadata and backend health endpoints.
- React console pages backed by these APIs. No dashboard figures or cases are generated locally.

The application does **not** capture traffic from a network interface or parse `.pcap` files. The console's **Import Flows** page accepts normalized JSON, JSONL, or NDJSON records and sends them to `POST /flows/batch`. PCAP conversion must happen outside this application before import. A successful import is scored and stored by the backend.

## Dashboard Pages

| Page | What it shows or does | Data source |
| --- | --- | --- |
| Overview | Counts and activity derived from the currently loaded flow, anomaly, and investigation records | `/flows`, `/anomalies`, `/investigations`, `/model/info`, `/health` |
| Flow Records | Search, inspect, and export ingested flow records with their scores | `/flows`, `/flows/{flow_id}` |
| Import Flows | Submit up to 500 normalized flow records per file | `POST /flows/batch` |
| Traffic Analytics | Protocol, destination-port, and source-host aggregates over loaded flows | `/flows`, `/anomalies` |
| Anomalies | Filter events, inspect their related flow, update status, and start an investigation | `/anomalies`, `/anomalies/{event_id}`, `PATCH /anomalies/{event_id}`, `POST /investigations/{event_id}` |
| Investigations | Review investigation state and collected evidence | `/investigations`, `/investigations/{id}/evidence` |
| Reports | List investigation cases, read generated reports, and submit analyst review status | `/investigations`, `/reports/{id}`, `POST /reports/{id}/review` |
| Model | Inspect active model metadata, feature order, and thresholds | `/model/info` |
| API Health | Inspect API, model, and optional LLM status | `/health` |
| Settings | Enable or disable the console's 15-second refresh | Local browser state only |
| Privacy Policy | Explain how this self-hosted console handles requests and telemetry | Static console content |

Counts and charts are computed from the API response window, which is capped at 500 records per feed. They are not totals across the entire database. The time-range control filters the records already loaded in the browser; it does not request historical pagination from the backend.

## Flow Import Format

Choose a `.json`, `.jsonl`, or `.ndjson` file. JSON may contain one record or an array; line-delimited formats contain one JSON object per line. Each record must include `src_ip`, `dst_ip`, `src_port`, and `dst_port`. Other accepted fields include `flow_id`, `timestamp`, `protocol`, `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, and `resp_pkts`.

Example:

```json
[
  {
    "timestamp": "2026-10-09T10:00:00Z",
    "src_ip": "192.0.2.10",
    "dst_ip": "198.51.100.20",
    "src_port": 51000,
    "dst_port": 443,
    "protocol": "TCP",
    "duration": 1.2,
    "orig_bytes": 1200,
    "resp_bytes": 2400,
    "orig_pkts": 8,
    "resp_pkts": 10
  }
]
```

The browser limits files to 10 MB and 500 records. The backend normalizes and featurizes each flow, scores it with the active detector, stores it, and creates an event when the score crosses a configured event threshold.

## Detection and Investigation

The detector scores normalized flow features. The threshold policy classifies scores below `monitor_at` as store-only, scores from `monitor_at` to below `investigate_at` for monitoring, and scores at or above `investigate_at` for investigation eligibility. Crossing the investigation threshold does not automatically run the agent: an analyst starts it from the anomaly details.

The investigation backend runs its LangGraph workflow, stores tool evidence, calculates risk, and creates a report. LLM enhancement is optional and controlled by the backend configuration. The console displays the returned investigation and report data; it does not create substitute results when the API is unavailable.

## Run Locally

### Backend

Use Python 3.10 or later.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

The API documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs). Configure optional model, database, and LLM settings using the environment variables read by the backend. The specific settings and defaults are defined in the application code and deployment configuration.

### Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). The Vite development proxy forwards `/api` requests to the local FastAPI service. Start the backend first; the console shows an unavailable state rather than fabricated records when it cannot connect.

## API Used by the Console

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Backend and optional LLM status |
| `GET` | `/flows` | List flows |
| `GET` | `/flows/{flow_id}` | Read a flow |
| `POST` | `/flows/ingest` | Score and store one flow |
| `POST` | `/flows/batch` | Score and store a batch of flows |
| `GET` | `/anomalies` | List anomaly events |
| `GET` | `/anomalies/{event_id}` | Read an anomaly event |
| `PATCH` | `/anomalies/{event_id}` | Update analyst triage status |
| `GET` | `/model/info` | Read active detector, features, and thresholds |
| `POST` | `/investigations/{event_id}` | Start or retrieve the event's investigation |
| `GET` | `/investigations` | List investigations |
| `GET` | `/investigations/{investigation_id}/evidence` | Read collected evidence |
| `GET` | `/reports/{report_id}` | Read a report |
| `POST` | `/reports/{report_id}/review` | Record report review status |

The API is also available through the FastAPI OpenAPI page at `/docs`.

## Privacy and Deployment

NetSentry is self-hosted software. The deployment operator controls API access, database configuration, and retention. The frontend sends telemetry to its configured backend and does not include analytics or advertising scripts. Optional backend integrations, including an LLM provider, may receive data as configured by the operator. Review the deployment and provider settings before importing sensitive telemetry or exposing the service publicly.

The in-app Privacy Policy describes the console behavior. There is no Terms and Conditions page because this repository is self-hosted software, not a hosted service with customer accounts or a commercial service agreement. Deployers should provide any additional notices required for their use case.

## Project Layout

```text
api/                 FastAPI application and routes
agent/               LangGraph workflow and deterministic tools
capture/             Flow normalization and JSONL source helpers
database/            SQLAlchemy models, repository, and database setup
events/              Threshold policy and anomaly event construction
features/            Flow feature extraction and feature schema
ml/                  Detector interface, implementations, and evaluation assets
reports/              Report construction
frontend/              React, TypeScript, and Vite console
tests/                 Backend and console contract tests
```

## License

This project is licensed under the [MIT License](LICENSE).
