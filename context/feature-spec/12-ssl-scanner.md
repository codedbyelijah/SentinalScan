Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the SSL/TLS analysis module used to inspect HTTPS certificates and TLS configurations.

No additional packages are required.

Create:

- `backend/scanners/ssl_scanner.py`

Dependencies:

- `backend/scanners/http_probe.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Analyze HTTPS targets only.
- Retrieve the server SSL/TLS certificate.
- Extract:
  - Subject
  - Issuer
  - Valid From
  - Expiration Date
  - TLS Version
- Detect expired certificates.
- Detect certificates nearing expiration.
- Return all findings using the shared `ScanResult` model.
- Handle invalid or unreachable certificates gracefully.

Do not:

- Perform vulnerability scanning.
- Modify certificates.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- The module implements the `ScanModule` interface.
- Certificate information is retrieved successfully.
- Expired certificates are detected.
- TLS version is identified.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
