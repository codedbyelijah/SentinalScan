Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the HTTP method analysis module.

Install the latest version.

```bash
uv add httpx
```

Create:

- `backend/scanners/http_method_scanner.py`

Dependencies:

- `backend/scanners/http_probe.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Discover supported HTTP methods.
- Check support for:
  - GET
  - POST
  - PUT
  - DELETE
  - PATCH
  - OPTIONS
  - HEAD
  - TRACE
- Identify potentially risky methods.
- Return results using the shared `ScanResult` model.

Do not:

- Exploit HTTP methods.
- Perform authentication bypass attempts.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Supported HTTP methods are detected.
- Risky methods are identified.
- Results use the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
