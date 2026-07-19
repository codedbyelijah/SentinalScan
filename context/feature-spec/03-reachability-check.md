Read `AGENTS.md`, `context/architecture.md`, and `context/code-standards.md` before starting.

We're building the reachability check service used before starting a scan.

Create:

- `backend/services/reachability_checker.py`

Use Python's standard library for ICMP ping and `httpx` for HTTP and HTTPS connectivity checks.

Install:

- httpx

Requirements:

- Accept the shared `Target` model.
- Check the reachability of URLs and domains using HTTP or HTTPS requests.
- Check the reachability of IPv4 and IPv6 addresses using the operating system's native `ping` command.
- Use Python's `subprocess` module to execute the `ping` command.
- Support Windows, Linux, and macOS by using the appropriate `ping` command arguments.
- Return whether the target is reachable.
- Return the response time when available.
- Handle timeouts and unreachable targets gracefully.
- Raise structured errors when a reachability check cannot be completed.

Do not:

- Perform port scanning.
- Detect running services.
- Perform DNS or subdomain enumeration.
- Start vulnerability scans.
- Create API endpoints.

### Check when done

- Reachable URLs return a successful status.
- Reachable domains return a successful status.
- Reachable IPv4 addresses return a successful status.
- Reachable IPv6 addresses return a successful status.
- Unreachable targets are handled gracefully.
- Response time is returned when available.
- The service works on Windows, Linux, and macOS.
- No lint or type errors exist.
