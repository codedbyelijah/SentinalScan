Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the report export service used to retrieve generated reports.

No additional packages are required.

Create:

- `backend/reports/report_export.py`

Dependencies:

- `backend/reports/report_generator.py`

Requirements:

- Locate generated reports.
- Export PDF reports.
- Export HTML reports.
- Export JSON reports.
- Validate requested report exists.
- Return structured errors when reports cannot be found.

Do not:

- Generate reports.
- Modify reports.
- Delete reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Existing reports are exported successfully.
- Missing reports return structured errors.
- All supported report formats are exported.
- No lint errors exist.
- No type errors exist.
