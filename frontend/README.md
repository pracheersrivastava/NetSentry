# NetSentry Analyst Console

React, TypeScript, Vite, Tailwind, Radix accessible primitives, Lucide, and Recharts.

## Run

Start the backend from the repository root using the project's Python environment:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, normally http://127.0.0.1:5173.
The development proxy forwards `/api` to `127.0.0.1:8000`; edit `vite.config.ts`
if the backend runs on a different port. For production, serve `dist` and reverse
proxy `/api` to FastAPI on the same origin.

```powershell
npm run build
```

## Data and Review

- Live mode is the default. Backend failures display a retryable error, never sample data.
- Settings exposes an explicit demo switch. Demo changes are in-memory and never call the backend.
- Each feed loads at most 500 records. Counts, date filters, charts, and exports refer to that loaded window, not all-time totals. A cap warning appears when a feed reaches 500.
- Flow scores reflect the currently active detector. Anomaly scores are stored detection scores.
- The UI displays the active version, including `v0-stub` when no compatible joblib artifact is installed.
- The backend supplies threshold values. Model controls are read-only because the backend has no threshold-update API.
- Investigations execute synchronously on the backend. The UI shows recorded stages after completion, without simulating real-time node progress.
- Evidence payloads remain inspectable. Newly executed investigations persist initial feature analysis; older cases can legitimately lack this evidence.
- Report approval/rejection uses the existing reviewer-status API. These are report decisions, not a new true/false-positive incident classification.
- Timestamps without an offset from SQLite are interpreted as UTC and displayed in the browser's local time zone.
- JSON exports are local downloads.

## Local Verification Environment

The machine's global Python environment had FastAPI 0.115.14 alongside an
incompatible Starlette. Verification used a project-local `.runtime` directory:

```powershell
python -m pip install --target .runtime "starlette>=0.40,<0.47"
$env:PYTHONPATH = "$PWD/.runtime"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

This directory is ignored. Prefer a clean virtual environment on other machines.
