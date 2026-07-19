Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're exposing the SentinelScan backend through REST API endpoints.

No additional packages are required.

Create:

- `backend/api/scan_routes.py`

Dependencies:

- `backend/orchestrator/scan_orchestrator.py`
- `backend/services/scan_scheduler.py`
- `backend/reports/report_export.py`

Requirements:

Create endpoints for:

- Start Scan
- Scan Status
- Scan Results
- Schedule Scan
- Cancel Scheduled Scan
- Export Report

Validate all request bodies.

Return consistent JSON responses.

Return appropriate HTTP status codes.

Do not:

- Implement scan logic.
- Generate reports.
- Duplicate validation logic.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- All endpoints respond successfully.
- Validation errors return structured responses.
- HTTP status codes are correct.
- No lint errors exist.
- No type errors exist.
