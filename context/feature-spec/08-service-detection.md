Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the service detection module used to identify services running on open ports.

No additional packages are required.

Create:

- `backend/scanners/service_detection.py`

Dependencies:

- `backend/scanners/port_scanner.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Analyze only ports identified as open.
- Detect common application protocols.
- Attempt banner grabbing where supported.
- Identify common services including:
  - HTTP
  - HTTPS
  - SSH
  - FTP
  - SMTP
  - POP3
  - IMAP
- Return detected services using the shared `ScanResult` model.
- Handle unsupported or unknown services gracefully.

Do not:

- Perform vulnerability scanning.
- Scan additional ports.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- The module implements the `ScanModule` interface.
- Only open ports are analyzed.
- Service banners are detected where available.
- Unknown services are handled gracefully.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
