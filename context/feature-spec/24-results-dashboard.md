Read `AGENTS.md`, `context/ui-context.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the results dashboard used to display completed scan results.

No additional packages are required.

Create:

- `frontend/components/dashboard/results-dashboard.tsx`

Dependencies:

- `frontend/components/dashboard/dashboard-layout.tsx`
- Backend Scan Results API
- Shared ScanResult model

Requirements:

- Display target information.
- Display scan summary.
- Display overall risk level.
- Display findings grouped by scan module.
- Display severity badges.
- Display scan duration.
- Display scan timestamp.
- Display scan errors when present.
- Allow navigation to the report viewer.

Do not:

- Execute scans.
- Generate reports.
- Modify scan results.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Scan summary displays correctly.
- Findings display correctly.
- Severity badges render correctly.
- Scan errors display correctly.
- Navigation to the report viewer works.
- No TypeScript errors exist.
- No lint errors exist.
