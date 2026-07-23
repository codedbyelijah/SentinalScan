# Architecture Context

## Stack

| Layer                | Technology               | Role                                                               |
| -------------------- | ------------------------ | ------------------------------------------------------------------ |
| Frontend             | Next.js + TypeScript     | Provides the web interface for interacting with SentinelScan.      |
| UI                   | Tailwind CSS + shadcn/ui | Builds responsive and reusable user interface components.          |
| Backend              | FastAPI                  | Exposes REST APIs and coordinates all scanning operations.         |
| CLI                  | Typer                    | Provides a command-line interface for running scans.               |
| Runtime              | Python 3.13+             | Executes the core application logic.                               |
| Port Scanning        | asyncio + socket         | Performs asynchronous TCP port scanning.                           |
| Reachability         | httpx + socket           | Verifies that targets are reachable before scanning.               |
| Web Security Scanner | httpx + BeautifulSoup4   | Performs lightweight web security analysis and content inspection. |
| SSL/TLS Analysis     | ssl + socket             | Inspects SSL/TLS certificates and protocol configurations.         |
| Technology Detection | httpx + BeautifulSoup4   | Identifies web technologies from HTTP responses and HTML content.  |
| Reporting            | ReportLab                | Generates downloadable PDF security reports.                       |
| Networking           | httpx                    | Performs asynchronous HTTP communication.                          |
| Async Engine         | asyncio                  | Enables concurrent execution of scanning modules.                  |

## System Boundaries

- `frontend/` — Owns the web user interface, user interactions, scan configuration, progress display, and report viewing.
- `backend/app/` — Main application directory containing all backend code.
- `backend/app/models/` — Owns shared Pydantic models and enums used across the backend.
- `backend/app/services/` — Owns validation services and business logic (e.g., target validation).
- `backend/app/scanners/` — Owns port scanning, reachability checking, web security analysis, SSL/TLS analysis, and technology detection modules.
- `backend/app/reports/` — Owns report formatting and PDF generation.
- `backend/app/core/` — Owns shared utilities including configuration, logging, helper functions.
- `backend/app/api/` — Owns FastAPI routes and request handling.
- `backend/app/orchestrator/` — Owns scan orchestration and workflow management.
- `cli/` — Owns command-line commands and communicates directly with backend services.

## Storage Model

- **Application Memory**: Stores scan progress, intermediate scan results, and execution state during runtime.
- **Generated Files**: Stores exported PDF security reports and temporary scan artifacts generated during execution.

## Auth and Access Model

- The system does not implement user authentication.
- The application is intended for use by a System Administrator within an authorized testing environment.
- Users are responsible for ensuring they have permission to scan the specified targets.
- The application does not maintain user accounts, permissions, or ownership records.

## Invariants

1. Every scan must pass target validation before any scanning module is executed.
2. Every target must pass the reachability check before scan execution begins.
3. The Scan Orchestrator is the only component responsible for coordinating scan modules.
4. Scan modules must implement the shared `ScanModule` interface.
5. Scan modules must remain independent and communicate only through the Scan Orchestrator.
6. All scan modules execute asynchronously.
7. Every scan module must return the shared `ScanResult` model.
8. Reports are generated only after all enabled scan modules have completed or returned their results.
9. Scan modules must not communicate directly with one another.
