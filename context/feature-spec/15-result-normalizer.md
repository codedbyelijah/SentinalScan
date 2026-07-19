Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the result normalization service used to convert scan outputs into a consistent format.

No additional packages are required.

Create:

- `backend/services/result_normalizer.py`

Dependencies:

- `backend/scanners/port_scanner.py`
- `backend/scanners/service_detection.py`
- `backend/scanners/http_probe.py`
- `backend/scanners/security_header_scanner.py`
- `backend/scanners/http_method_scanner.py`
- `backend/scanners/ssl_scanner.py`
- `backend/scanners/technology_detector.py`
- `backend/scanners/content_discovery.py`
- Shared `ScanResult` model

Requirements:

- Normalize results from every scan module.
- Preserve the source module for each finding.
- Convert findings into the shared data model.
- Preserve severity information.
- Preserve scan errors.
- Return a consolidated `ScanResult`.

Do not:

- Execute scan modules.
- Calculate risk scores.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Results from all scan modules are normalized.
- Source module information is preserved.
- Scan errors are preserved.
- A consolidated `ScanResult` is returned.
- No lint errors exist.
- No type errors exist.
