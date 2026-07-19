Read `AGENTS.md`, `context/ui-context.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the report viewer used to preview and download generated reports.

No additional packages are required.

Create:

- `frontend/components/dashboard/report-viewer.tsx`

Dependencies:

- `backend/reports/report_export.py`
- `frontend/components/dashboard/results-dashboard.tsx`

Requirements:

- Display report metadata.
- Preview HTML reports.
- Provide download actions for:
  - PDF
  - HTML
  - JSON
- Display report generation timestamp.
- Display report size.
- Display report format.
- Handle missing reports gracefully.

Do not:

- Generate reports.
- Execute scans.
- Modify reports.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- HTML reports preview correctly.
- PDF download works.
- HTML download works.
- JSON download works.
- Missing reports display an appropriate error.
- No TypeScript errors exist.
- No lint errors exist.
