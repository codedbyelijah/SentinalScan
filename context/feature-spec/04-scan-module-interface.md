Read `AGENTS.md`, `context/architecture.md`, and `context/code-standards.md` before starting.

We're creating the shared scan module interface used by all scanning modules.

Create:

- `backend/scanners/scan_module.py`

Requirements:

- Create a `ScanModule` interface.
- Define an asynchronous `scan()` method.
- The `scan()` method should accept the shared `Target` model.
- The `scan()` method should return the shared `ScanResult` model.
- Document the purpose of the interface.
- Ensure future scan modules can implement the interface without modification.

Do not:

- Implement any scanning logic.
- Create concrete scan modules.
- Perform network requests.
- Create API endpoints.

### Check when done

- The `ScanModule` interface imports without errors.
- The `scan()` method is asynchronous.
- The interface accepts the shared `Target` model.
- The interface returns the shared `ScanResult` model.
- No lint or type errors exist.
