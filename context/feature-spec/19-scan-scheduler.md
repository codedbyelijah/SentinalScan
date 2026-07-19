Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the scan scheduling service that enables automated scanning.

Install the latest version.

```bash
uv add apscheduler
```

Create:

- `backend/services/scan_scheduler.py`

Dependencies:

- `backend/orchestrator/scan_orchestrator.py`
- Shared `ScanRequest` model

Requirements:

- Schedule one-time scans.
- Schedule recurring scans.
- Support:
  - Hourly
  - Daily
  - Weekly
  - Custom Interval
- Allow scheduled scans to be cancelled.
- Prevent duplicate scheduled jobs.
- Execute scans through the Scan Orchestrator.
- Return scheduler status information.

Do not:

- Execute scan logic directly.
- Generate reports.
- Store schedules in a database.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- One-time scans execute successfully.
- Recurring scans execute successfully.
- Scheduled jobs can be cancelled.
- Duplicate schedules are prevented.
- No lint errors exist.
- No type errors exist.
