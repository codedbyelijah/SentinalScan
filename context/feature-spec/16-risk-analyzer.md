Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the risk analysis service used to evaluate scan findings and calculate an overall security assessment.

No additional packages are required.

Create:

- `backend/services/risk_analyzer.py`

Dependencies:

- `backend/services/result_normalizer.py`
- Shared `ScanResult` model

Requirements:

- Analyze normalized scan findings.
- Assign severity levels.
- Calculate an overall risk level.
- Generate a security summary.
- Record the total number of:
  - Findings
  - Warnings
  - Errors
- Return the updated `ScanResult` model.

Do not:

- Execute scan modules.
- Modify scan findings.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Risk levels are calculated.
- Findings are summarized.
- Overall scan risk is produced.
- The updated `ScanResult` model is returned.
- No lint errors exist.
- No type errors exist.
