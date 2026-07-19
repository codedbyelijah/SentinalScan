# Code Standards

## General

- Keep modules small and focused on a single responsibility.
- Prefer composition over tightly coupled implementations.
- Fix root causes instead of introducing temporary workarounds.
- Use descriptive names for modules, functions, variables, and classes.
- All scan modules must be reusable and independent.
- Avoid duplicate logic by extracting shared functionality into reusable utilities.
- Every function should include appropriate error handling and logging where necessary.

## Python

- Follow PEP 8 coding standards.
- Use Python type hints for all public functions and methods.
- Use dataclasses or Pydantic models for structured data where appropriate.
- Validate all external input before processing.
- Prefer asynchronous (`async`/`await`) implementations for I/O-bound operations.
- Raise meaningful exceptions instead of silently ignoring errors.
- Keep business logic separate from API routes.

## FastAPI

- Keep route handlers lightweight.
- Business logic belongs in service or scanner modules, not API endpoints.
- Validate request data using Pydantic models.
- Return consistent JSON response structures.
- Use dependency injection where appropriate.
- Do not execute long-running scans directly inside route handlers.

## Styling

- Use Tailwind CSS utility classes consistently.
- Build reusable UI components with shadcn/ui.
- Maintain a clean and responsive interface.
- Avoid inline styles unless absolutely necessary.

## API Routes

- Validate all request data before processing.
- Return appropriate HTTP status codes.
- Use consistent response formats for success and error responses.
- Do not expose internal exception details to clients.
- Keep each endpoint focused on a single responsibility.

## Data and Storage

- Do not use a database for this project.
- Store scan results only during runtime unless exported by the user.
- Generated reports should be saved as downloadable PDF files.
- Temporary files should be removed after use where appropriate.

## File Organization

- `frontend/` — Next.js user interface and reusable UI components.
- `backend/api/` — FastAPI routes and request handling.
- `backend/core/` — Shared utilities, configuration, validation, and logging.
- `backend/orchestrator/` — Scan orchestration and workflow management.
- `backend/scanners/` — Reconnaissance, port scanning, and web vulnerability scanning modules.
- `backend/reports/` — Report generation and PDF export.
- `cli/` — Command-line interface implementation.
- `tests/` — Unit and integration tests.
