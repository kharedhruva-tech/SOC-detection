# AI-Integrated SOC Platform (SOC-detection)

A full-stack Security Operations Center (SOC) simulation platform that brings together SIEM-style detection, UEBA, threat intelligence, digital forensics, SOAR automation, and an AI security analyst into a single real-time dashboard.

**Live demo:** [soc-detection.vercel.app](https://soc-detection.vercel.app)

---

## Overview

SOC-detection simulates the day-to-day workflow of a Security Operations Center. A background log generator continuously produces synthetic security events, a detection engine matches them against a rule set mapped to MITRE ATT&CK techniques, and the resulting alerts, incidents, and analytics stream live to a Next.js dashboard over WebSockets. Analysts can triage alerts, run automated response playbooks, investigate assets and user behavior, and get natural-language explanations of threats from an AI-assisted analyst module.

This project was built as a portfolio/learning platform to demonstrate SIEM, SOAR, UEBA, and threat-intel concepts in an interactive, end-to-end application.

## Features

- **Real-time SIEM engine** – synthetic log generator + rule-based detection engine that raises alerts (e.g. brute-force attacks, ransomware-style file activity) mapped to MITRE ATT&CK tactics/techniques
- **Live alert streaming** – WebSocket channel (`/ws/alerts`) pushes new alerts to the dashboard as they're generated
- **Incident management** – incident timeline, tasks, and lifecycle tracking
- **SOAR playbooks** – automated response playbooks that can be triggered against incidents
- **UEBA (User & Entity Behavior Analytics)** – behavioral anomaly views for users and assets
- **Threat intelligence** – IOC (Indicator of Compromise) tracking with reputation and threat-actor context
- **Digital forensics** – forensic investigation views tied to incidents
- **AI Analyst** – natural-language alert explanations, with optional integration for real LLM-backed analysis
- **Reporting** – SOC reporting views for incidents and detections
- **Auth** – JWT-based authentication with role-based demo accounts (Super Admin / SOC User)

## Tech Stack

**Frontend**
- [Next.js 16](https://nextjs.org/) (App Router) + React 19 + TypeScript
- Tailwind CSS 4
- Recharts (analytics/charts), React Flow (playbook/graph visualization), Framer Motion (animations), Lucide icons

**Backend**
- [FastAPI](https://fastapi.tiangolo.com/) (Python)
- SQLAlchemy ORM with SQLite (default) or PostgreSQL
- JWT auth (PyJWT + Passlib/bcrypt)
- WebSockets for live alert streaming

**Deployment**
- Frontend: [Vercel](https://vercel.com/)
- Backend: [Render](https://render.com/) (see `render.yaml` / `Procfile`)

## Architecture

```
┌─────────────────┐        REST (/api/v1)        ┌──────────────────────┐
│                 │ ────────────────────────────▶ │                      │
│  Next.js        │                                │  FastAPI Backend     │
│  Frontend        │ ◀──────────────────────────── │                      │
│  (Vercel)        │        WebSocket (/ws/alerts) │  - SIEM engine       │
│                 │ ◀════════════════════════════ │  - SOAR executor     │
└─────────────────┘        live alert stream      │  - AI analyst        │
                                                    │  - Log generator     │
                                                    │  - UEBA / Intel      │
                                                    └──────────┬───────────┘
                                                               │
                                                    ┌──────────▼───────────┐
                                                    │  SQLite / PostgreSQL │
                                                    └──────────────────────┘
```

## Project Structure

```
SOC-detection/
├── backend/
│   ├── app/
│   │   ├── api/routers/       # auth, incidents, alerts, playbooks, assets,
│   │   │                      # reports, ueba, intel, forensics
│   │   ├── models/            # SQLAlchemy models & Pydantic schemas
│   │   ├── services/          # siem_engine, soar_executor, ai_agent,
│   │   │                      # ai_analyst, log_generator, ws_manager
│   │   ├── config.py          # environment-based settings
│   │   ├── database.py        # DB session/engine setup
│   │   └── database_seed.py   # demo data & default accounts
│   └── requirements.txt
├── frontend/
│   ├── src/app/
│   │   ├── dashboard/         # siem, soar, ueba, intel, forensics,
│   │   │                      # incidents, reports, hunting, vulnerability
│   │   ├── ai-analyst/
│   │   ├── alerts/
│   │   ├── incidents/
│   │   ├── login/
│   │   └── playbooks/
│   └── package.json
├── Procfile
└── render.yaml
```

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ (Next.js 16 requires a recent Node version)
- npm / yarn / pnpm

### Backend Setup

```bash
git clone https://github.com/kharedhruva-tech/SOC-detection.git
cd SOC-detection

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Run the API
uvicorn backend.app.services.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`, with interactive docs at `http://localhost:8000/docs`.

By default the backend uses a local SQLite database (`soc_platform.db`) and seeds it automatically on startup with demo data, including sample users, incidents, alerts, and IOCs.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The app will be available at `http://localhost:3000`. Point it at your local backend by configuring the API base URL (see `frontend/src` for the API client configuration) if you're not using the deployed backend.

### Environment Variables (Backend)

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | JWT signing secret | dev placeholder — set a real value in production |
| `USE_POSTGRES` | Use PostgreSQL instead of SQLite | `false` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_SERVER` / `POSTGRES_PORT` / `POSTGRES_DB` | PostgreSQL connection settings (used when `USE_POSTGRES=true`) | — |
| `SQLITE_DB_PATH` | Path to local SQLite file | `soc_platform.db` |

## Deployment

- **Frontend** is deployed on Vercel: [soc-detection.vercel.app](https://soc-detection.vercel.app)
- **Backend** is configured for Render via `render.yaml`, which installs dependencies from `backend/requirements.txt` and starts the API with:
  ```bash
  uvicorn backend.app.services.main:app --host 0.0.0.0 --port $PORT
  ```

## API Overview

All backend routes are namespaced under `/api/v1`:

| Route prefix | Purpose |
|---|---|
| `/auth` | Login / authentication |
| `/incidents` | Incident lifecycle management |
| `/alerts` | Alert retrieval and triage |
| `/playbooks` | SOAR playbook management & execution |
| `/assets` | Monitored asset inventory |
| `/reports` | SOC reporting |
| `/ueba` | User & entity behavior analytics |
| `/intel` | Threat intelligence / IOCs |
| `/forensics` | Digital forensics investigation data |

Live alerts are streamed over a WebSocket at `/ws/alerts`.

## Disclaimer

This is a **simulation/demo platform** intended for learning and portfolio purposes. Logs, alerts, and threat intelligence are synthetically generated and should not be used as a real production security monitoring solution.

## License

No license has been specified for this project. All rights reserved by the author unless a license is added.

## Author

Built by [kharedhruva-tech](https://github.com/kharedhruva-tech).
