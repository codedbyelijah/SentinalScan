Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the security header analysis module.

Install the latest version.

```bash
uv add httpx
```

Create:

- `backend/scanners/security_header_scanner.py`

Dependencies:

- `backend/scanners/http_probe.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Analyze HTTP response headers.
- Check for:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Report missing headers.
- Report misconfigured headers.
- Return results using the shared `ScanResult` model.

Do not:

- Modify HTTP headers.
- Perform penetration testing.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- All required headers are analyzed.
- Missing headers are reported.
- Misconfigured headers are reported.
- Results use the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
