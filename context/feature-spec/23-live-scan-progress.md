Read `AGENTS.md`, `context/ui-context.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the live scan progress interface used to display scan execution in real time.

No additional packages are required.

Create:

- `frontend/components/dashboard/live-scan-progress.tsx`

Dependencies:

- `frontend/components/dashboard/dashboard-layout.tsx`
- `frontend/components/dashboard/scan-configuration.tsx`
- Backend Scan Status API

Requirements:

- Display scan status in real time.
- Display the current module being executed.
- Display completed modules.
- Display pending modules.
- Display failed modules.
- Display an overall progress indicator.
- Display elapsed scan time.
- Handle scan failures gracefully.
- Refresh progress without requiring a full page reload.

Do not:

- Execute scans.
- Display scan findings.
- Display generated reports.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Progress updates correctly.
- Current module is displayed.
- Completed modules are displayed.
- Failed modules are displayed.
- Progress indicator updates correctly.
- No TypeScript errors exist.
- No lint errors exist.
