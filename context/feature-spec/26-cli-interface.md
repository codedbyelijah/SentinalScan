Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

Install the latest version.

```bash
uv add typer rich
```

We're building the SentinelScan command-line interface.

Create:

- `cli/main.py`

Dependencies:

- `backend/orchestrator/scan_orchestrator.py`
- `backend/services/scan_scheduler.py`
- `backend/reports/report_export.py`
- Shared ScanRequest model

Requirements:

Implement the following commands:

- scan
- status
- schedule
- cancel
- export
- version
- help

Support:

- Target URL or IP input.
- Full Scan mode.
- Custom Scan mode.
- Report export.
- Colored terminal output.
- Progress display.
- Structured error messages.

Do not:

- Duplicate backend logic.
- Duplicate validation logic.
- Generate reports directly.
- Implement scan modules.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- All commands execute successfully.
- Help command displays correctly.
- Progress output is displayed.
- Report export works.
- Errors are displayed clearly.
- No lint errors exist.
- No type errors exist.
