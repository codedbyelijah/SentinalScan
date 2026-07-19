Read `AGENTS.md`, `context/architecture.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the content discovery module used to identify publicly accessible resources.

Create:

- `backend/scanners/content_discovery.py`

Dependencies:

- `backend/scanners/http_probe.py`
- Shared `Target` model
- Shared `ScanModule` interface
- Shared `ScanResult` model

Requirements:

- Implement the shared `ScanModule` interface.
- Accept the shared `Target` model.
- Check for common resources including:
  - robots.txt
  - sitemap.xml
  - favicon.ico
  - security.txt
- Check for common administrative pages.
- Detect directory listing where exposed.
- Record discovered resources.
- Return findings using the shared `ScanResult` model.
- Handle inaccessible resources gracefully.

Do not:

- Brute-force directories.
- Crawl the website recursively.
- Perform vulnerability scanning.
- Generate reports.
- Create API endpoints.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- The module implements the `ScanModule` interface.
- Common resources are detected.
- Directory listing is identified where available.
- Results are returned using the shared `ScanResult` model.
- No lint errors exist.
- No type errors exist.
