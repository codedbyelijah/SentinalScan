Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the HTTP probing module used to gather basic information from web services.

Install the latest version.

```bash
uv add httpx
```

Create:

- `backend/scanners/http_probe.py`

Dependencies:

- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Send HTTP and HTTPS requests.
- Detect the final reachable URL.
- Record:
  - Status code
  - Response time
  - Redirect chain
  - Server header
  - Response headers
- Handle unreachable targets gracefully.
- Return results using the shared `ScanResult` model.

Do not:

- Perform vulnerability scanning.
- Analyze SSL certificates.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- HTTP requests execute successfully.
- HTTPS requests execute successfully.
- Redirects are recorded.
- Response time is measured.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
