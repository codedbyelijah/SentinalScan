Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the report generation service responsible for creating security assessment reports.

Install the latest version.

```bash
uv add reportlab jinja2
```

Create:

- `backend/reports/report_generator.py`

Dependencies:

- `backend/services/result_normalizer.py`
- `backend/services/risk_analyzer.py`
- Shared `ScanResult` model

Requirements:

- Generate PDF reports.
- Generate HTML reports.
- Generate JSON reports.
- Include:
  - Scan Summary
  - Target Information
  - Scan Configuration
  - Findings
  - Risk Summary
  - Timestamp
- Save reports to the configured output directory.
- Return metadata about generated reports.

Do not:

- Execute scan modules.
- Modify scan results.
- Upload reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- PDF report is generated successfully.
- HTML report is generated successfully.
- JSON report is generated successfully.
- Reports contain all required sections.
- Generated file paths are returned.
- No lint errors exist.
- No type errors exist.
