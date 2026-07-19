Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the Scan Orchestrator, which is responsible for coordinating the execution of all scan modules.

Create:

- `backend/orchestrator/scan_orchestrator.py`

Requirements:

- Accept the shared `ScanRequest` model.
- Accept a collection of registered `ScanModule` implementations.
- Execute scan modules asynchronously using `asyncio`.
- Run all enabled scan modules concurrently.
- Wait for all enabled scan modules to complete.
- Continue executing remaining scan modules if one module fails.
- Collect successful scan results.
- Collect scan errors without terminating the scan.
- Return a consolidated `ScanResult`.
- Log the start and completion of every scan module.
- Ensure the orchestrator is independent of the implementation details of each scan module.

Do not:

- Implement any scan module logic.
- Perform target validation.
- Perform reachability checks.
- Generate reports.
- Expose API endpoints.
- Write scan results to disk.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Multiple scan modules execute concurrently.
- A failed scan module does not stop the remaining modules.
- Successful scan results are collected.
- Scan errors are collected separately.
- A consolidated `ScanResult` is returned.
- The orchestrator remains independent of scan module implementations.
- No lint errors exist.
- No type errors exist.
