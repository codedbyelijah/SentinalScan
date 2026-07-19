Read `AGENTS.md`, `context/architecture.md`, and `context/code-standards.md` before starting.

We're building the target validation service used throughout SentinelScan.

Create:

- `backend/services/target_validator.py`

Use Python's standard library and the project's existing Pydantic models. Do not install additional packages.

Requirements:

- Accept URLs, domains, IPv4 addresses, and IPv6 addresses.
- Automatically prepend `https://` when no protocol is provided.
- Normalize the target before validation.
- Determine the target type (URL, domain, IPv4, or IPv6).
- Validate the normalized target.
- Return the shared `Target` model.
- Raise structured validation errors for invalid input.

Do not:

- Check if the target is reachable.
- Perform DNS lookups.
- Send HTTP requests.
- Start any scan.
- Create API endpoints.

### Check when done

- URLs validate successfully.
- Domains validate successfully.
- IPv4 addresses validate successfully.
- IPv6 addresses validate successfully.
- Invalid targets return structured validation errors.
- The service returns the shared `Target` model.
- No lint or type errors exist.
