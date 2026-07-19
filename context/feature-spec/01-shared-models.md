Read `AGENTS.md`, `context/architecture.md`, and `context/code-standards.md` before starting.

We're creating the shared data models used across the backend.

Use **Pydantic v2** for all models.

Create a new `backend/models/` package.

Create the following models:

- Target
- ScanRequest
- ScanResult
- Finding
- Report

Requirements:

### Target

Should contain:

- original_input
- normalized_target
- target_type (domain, url, ipv4, ipv6)
- protocol

### ScanRequest

Should contain:

- target
- scan_mode (full, custom)
- enabled_modules

### Finding

Should contain:

- title
- description
- severity
- category
- affected_target
- recommendation

### ScanResult

Should contain:

- module_name
- status
- execution_time
- findings

### Report

Should contain:

- target
- generated_at
- scan_duration
- overall_status
- results

Create shared enums where appropriate.

Models should support serialization and validation.

Do not implement any business logic.

Do not perform validation.

Do not create API endpoints.

Do not create database models.

### Check when done

- All models import successfully.
- No circular imports exist.
- Models serialize correctly.
- Models validate input correctly.
- No scanning logic has been implemented.
