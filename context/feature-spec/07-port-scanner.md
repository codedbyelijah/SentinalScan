Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the asynchronous TCP port scanning module.

No additional packages are required.

Create:

- `backend/scanners/port_scanner.py`

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Use `asyncio` for concurrent port scanning.
- Use Python's `socket` library to test TCP connectivity.
- Support configurable port ranges.
- Support configurable connection timeout.
- Detect open and closed ports.
- Return discovered open ports in the shared `ScanResult`.
- Handle connection failures gracefully.

Do not:

- Perform service detection.
- Perform vulnerability scanning.
- Perform SSL/TLS analysis.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- The module implements the `ScanModule` interface.
- Multiple ports are scanned concurrently.
- Open ports are detected correctly.
- Closed ports are handled correctly.
- Connection timeouts are handled gracefully.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
