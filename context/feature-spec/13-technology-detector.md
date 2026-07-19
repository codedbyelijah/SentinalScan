Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the technology detection module used to identify technologies powering a web application.

Install the latest version.

```bash
uv add  beautifulsoup4
```

Create:

- `backend/scanners/technology_detector.py`

Dependencies:

- `backend/scanners/http_probe.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Analyze HTTP response headers.
- Analyze HTML source code.
- Analyze response cookies.
- Detect common technologies including:
  - Web Server
  - Programming Language
  - Framework
  - Content Management System (CMS)
- Return detected technologies using the shared `ScanResult` model.
- Handle unknown technologies gracefully.

Do not:

- Fingerprint operating systems.
- Perform vulnerability scanning.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- The module implements the `ScanModule` interface.
- Common technologies are detected.
- Unknown technologies are handled gracefully.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
