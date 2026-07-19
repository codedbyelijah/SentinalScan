# SentinelScan Backend Agent

Read `../AGENTS.md` before starting any implementation.

You are responsible only for the FastAPI backend.

## Backend Rules

- Follow the modular architecture.
- Keep business logic separate from API routes.
- Reuse shared models.
- Validate every external input.
- Prefer Python standard library before adding third-party packages.
- Use asynchronous APIs where appropriate.
- Keep modules independent.
- Route communication through the Scan Orchestrator.
- Do not implement frontend functionality.
