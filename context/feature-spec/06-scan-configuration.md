Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the scan configuration service used to prepare scan requests before execution.

Create:

- `backend/services/scan_configuration.py`

Requirements:

- Support Full Scan mode.
- Support Custom Scan mode.
- Allow enabling or disabling scan modules.
- Validate the selected scan mode.
- Validate the selected scan modules.
- Apply sensible default configuration values.
- Build and return the shared `ScanRequest` model.
- Ensure the configuration is compatible with the Scan Orchestrator.

Do not:

- Execute scan modules.
- Perform target validation.
- Perform reachability checks.
- Generate reports.
- Create API endpoints.
- Store configuration in a database.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Full Scan configuration is created successfully.
- Custom Scan configuration is created successfully.
- Invalid scan modes return structured errors.
- Invalid scan module selections return structured errors.
- A valid `ScanRequest` model is returned.
- No lint errors exist.
- No type errors exist.
